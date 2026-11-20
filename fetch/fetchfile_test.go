package fetch

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func hexOf(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func TestFetchFileCopiesTheBytesUnextracted(t *testing.T) {
	// A gzip stream is the case that matters: Fetch would unpack it, FetchFile
	// must leave it exactly as it arrived.
	body := gzWrap(t, sampleTar(t))
	s := serve(t, body)
	dir := filepath.Join(t.TempDir(), "deep", "er")
	got, err := FetchFile(s.URL+"/dir/pkg.tar.gz?download=1#frag", dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != hexOf(body) {
		t.Errorf("digest = %s, want %s", got, hexOf(body))
	}
	data, err := os.ReadFile(filepath.Join(dir, "pkg.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(body) {
		t.Error("the file on disk is not the bytes that arrived")
	}
	if st, _ := os.Stat(filepath.Join(dir, "pkg.tar.gz")); st.Mode().Perm() != 0o644 {
		t.Errorf("mode = %v, want 0644", st.Mode().Perm())
	}
}

func TestFetchFileRefusesAURLThatNamesNoFile(t *testing.T) {
	for _, u := range []string{
		"https://example.org",
		"https://example.org/",
		"https://example.org/dir/",
		"https://example.org/..",
		"https://example.org/a%5Cb",
		"https://example.org/a%00b",
		"http://[::1",
	} {
		dir := t.TempDir()
		if _, err := FetchFile(u, dir); err == nil {
			t.Errorf("%q: want an error", u)
		}
		if ents, _ := os.ReadDir(dir); len(ents) != 0 {
			t.Errorf("%q: wrote %d entries before refusing", u, len(ents))
		}
	}
}

// A URL that names no file is refused BEFORE anything is downloaded.
func TestFetchFileRefusesBeforeContactingTheServer(t *testing.T) {
	hits := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		_, _ = w.Write([]byte("x"))
	}))
	defer s.Close()
	dir := t.TempDir()
	if digest, err := FetchFile(s.URL+"/dir/", dir); err == nil || digest != "" {
		t.Errorf("got %q, %v", digest, err)
	}
	if hits != 0 {
		t.Errorf("the server was contacted %d times", hits)
	}
}

func TestFetchFileReportsAnOpenFailureAsOne(t *testing.T) {
	s := serve(t, []byte("body"))
	restoreSeams(t)
	osOpen = func(string) (*os.File, error) { return nil, errors.New("boom") }
	dir := t.TempDir()
	digest, err := FetchFile(s.URL+"/x.pem", dir)
	if err == nil || !strings.Contains(err.Error(), "fetch: open") || digest == "" {
		t.Errorf("got %q, %v", digest, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "x.pem")); err == nil {
		t.Error("a file was written although the temp file could not be opened")
	}
}

func TestFetchFileNeverOverwrites(t *testing.T) {
	s := serve(t, []byte("new"))
	dir := t.TempDir()
	target := filepath.Join(dir, "x.pem")
	if err := os.WriteFile(target, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := FetchFile(s.URL+"/x.pem", dir)
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("err = %v, want an already-exists refusal", err)
	}
	if got != hexOf([]byte("new")) {
		t.Errorf("digest = %q: what arrived is still reported", got)
	}
	if b, _ := os.ReadFile(target); string(b) != "old" {
		t.Errorf("file = %q, want untouched", b)
	}
	// A dangling symlink counts as existing, and is not followed.
	link := filepath.Join(dir, "l.pem")
	if err := os.Symlink(filepath.Join(dir, "elsewhere"), link); err != nil {
		t.Skipf("no symlinks: %v", err)
	}
	if _, err := FetchFile(s.URL+"/l.pem", dir); err == nil {
		t.Error("wrote through a symlink")
	}
	if _, err := os.Stat(filepath.Join(dir, "elsewhere")); err == nil {
		t.Error("the symlink target was created")
	}
}

func TestFetchFileFailures(t *testing.T) {
	s := serve(t, []byte("body"))
	t.Run("http status", func(t *testing.T) {
		bad := httptest.NewServer(http.HandlerFunc(http.NotFound))
		defer bad.Close()
		if _, err := FetchFile(bad.URL+"/x.pem", t.TempDir()); err == nil {
			t.Error("want an error")
		}
	})
	t.Run("digest", func(t *testing.T) {
		t.Cleanup(func() { osOpenHash = os.Open })
		osOpenHash = func(string) (*os.File, error) { return nil, errors.New("boom") }
		if _, err := FetchFile(s.URL+"/x.pem", t.TempDir()); err == nil || !strings.Contains(err.Error(), "digest") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("mkdir", func(t *testing.T) {
		restoreSeams(t)
		osMkdirAll = func(string, os.FileMode) error { return errors.New("boom") }
		got, err := FetchFile(s.URL+"/x.pem", t.TempDir())
		if err == nil || got == "" {
			t.Errorf("got %q, %v", got, err)
		}
	})
	t.Run("open", func(t *testing.T) {
		restoreSeams(t)
		osOpen = func(string) (*os.File, error) { return nil, errors.New("boom") }
		if _, err := FetchFile(s.URL+"/x.pem", t.TempDir()); err == nil {
			t.Error("want an error")
		}
	})
	t.Run("write", func(t *testing.T) {
		restoreSeams(t)
		ioCopy = func(io.Writer, io.Reader) (int64, error) { return 0, errors.New("boom") }
		if _, err := FetchFile(s.URL+"/x.pem", t.TempDir()); err == nil {
			t.Error("want an error")
		}
	})
	t.Run("the pin refuses", func(t *testing.T) {
		Pin = func(string, string) error { return ErrSourcePinMismatch }
		defer func() { Pin = nil }()
		dir := t.TempDir()
		if _, err := FetchFile(s.URL+"/x.pem", dir); !errors.Is(err, ErrSourcePinMismatch) {
			t.Errorf("err = %v", err)
		}
		if _, err := os.Stat(filepath.Join(dir, "x.pem")); err == nil {
			t.Error("the file was written after the pin refused")
		}
	})
}

func TestFetchFileTellsTheMirror(t *testing.T) {
	s := serve(t, []byte("pem"))
	var seen string
	Mirror = func(path, sha, url string) { seen = fmt.Sprintf("%s %s", sha, url) }
	defer func() { Mirror = nil }()
	if _, err := FetchFile(s.URL+"/x.pem", t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if want := hexOf([]byte("pem")) + " " + s.URL + "/x.pem"; seen != want {
		t.Errorf("mirror saw %q, want %q", seen, want)
	}
}
