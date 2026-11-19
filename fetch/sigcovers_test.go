package fetch

import (
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	uxz "github.com/ulikunitz/xz"
)

// go-zpkg/zpkb#492: kernel.org signs the UNCOMPRESSED tar, so the bytes a
// recipe pins and the bytes the signature covers are two different streams.
//
// ⛔ EVERY TEST HERE CARRIES ITS CONTROL IN THE SAME FUNCTION, because the
// positive alone is worthless: a check that accepts the decompressed stream
// would also pass if it had stopped checking anything. The controls are "the
// served bytes are still refused", "another key is still refused", and "one
// flipped byte is still refused".

// atPaths serves a body per path, so an archive and its signature can live at
// the names upstream actually publishes.
func atPaths(t *testing.T, files map[string][]byte) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	for path, body := range files {
		b := body
		mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) { w.Write(b) })
	}
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

func sha256of(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// xzOf compresses with ulikunitz/xz, DELIBERATELY not the decoder under test.
// artifactpkg/comparecodec_test.go makes the same choice for the same reason:
// one implementation on both sides of a round trip can agree with itself about
// a stream neither reads correctly.
func xzOf(t *testing.T, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := uxz.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func gzOf(t *testing.T, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// ⛔⛔ TestTheKernelOrgShape is the whole of go-zpkg/zpkb#492, in the smallest
// arrangement that still has both bytes streams in it: a signature made over
// the plain tar, an archive served compressed, and a digest that must come out
// as the COMPRESSED file's because that is what a build downloads.
func TestTheKernelOrgShape(t *testing.T) {
	key := testKey(t)
	ring := armoredPublicKey(t, key)
	plain := []byte("this stands in for linux-7.2.15.tar, and it is what the .sign covers\n")
	comp := xzOf(t, plain)
	// Armoured, which is what kernel.org publishes: its .sign files open with
	// -----BEGIN PGP SIGNATURE----- and carry the explanation in the header.
	sig := detach(t, key, plain, true)

	srv := atPaths(t, map[string][]byte{
		"/linux-7.2.15.tar.xz":   comp,
		"/linux-7.2.15.tar.sign": sig,
	})
	url := srv.URL + "/linux-7.2.15.tar.xz"
	sigURLs := []string{srv.URL + "/linux-7.2.15.tar.sign"}

	pin, err := DigestVerifiedDecompressed(url, sigURLs, ring, "")
	if err != nil {
		t.Fatalf("DigestVerifiedDecompressed: %v", err)
	}
	// ⭐ THE PIN IS THE COMPRESSED FILE'S AND THE WARRANT IS OVER THE OTHER
	// STREAM. If these two were ever the same value the test would be measuring
	// nothing, so both are asserted by name.
	if want := sha256of(comp); pin.SHA256 != want {
		t.Errorf("SHA256 = %s, want the COMPRESSED file's %s", pin.SHA256, want)
	}
	if pin.SHA256 == sha256of(plain) {
		t.Error("SHA256 is the decompressed stream's: a build downloads the compressed file")
	}
	if pin.Size != int64(len(comp)) {
		t.Errorf("Size = %d, want the compressed file's %d", pin.Size, len(comp))
	}
	if pin.Covers != CoversDecompressed {
		t.Errorf("Covers = %q, want %q", pin.Covers, CoversDecompressed)
	}

	// ⛔⛔ THE CONTROL, AND IT IS THE DEFECT. Before this existed the only
	// available call was this one, and it is right to refuse: these bytes are
	// not the signed ones. The refusal must also POINT somewhere, because a
	// good key and a good signature failing with "RSA verification failure"
	// cost go-zpkg/zpkb#492 a day of looking at the key.
	_, err = DigestVerified(url, sigURLs, ring, "")
	if err == nil {
		t.Fatal("DigestVerified accepted a signature made over the decompressed archive")
	}
	for _, want := range []string{"not vouched for", "--sig-covers decompressed", "UNCOMPRESSED"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not mention %q:\n%v", want, err)
		}
	}
}

// TestDecompressedCoversEveryCompressedFormat: the same arrangement through
// gzip and bzip2, because the decompressor is chosen per format and a branch
// that is never driven is a branch nobody has run.
func TestDecompressedCoversEveryCompressedFormat(t *testing.T) {
	key := testKey(t)
	ring := armoredPublicKey(t, key)

	// bzip2 has no writer in the standard library, so the FIXTURE is the
	// compressed side and the plain side is read back out of it — the opposite
	// direction from the other two, and the only one available.
	bz2, err := hex.DecodeString(bz2TarHex)
	if err != nil {
		t.Fatal(err)
	}
	bzPlain, err := io.ReadAll(bzip2.NewReader(bytes.NewReader(bz2)))
	if err != nil {
		t.Fatal(err)
	}

	gzPlain := []byte("a plain tar, signed as such\n")

	for _, c := range []struct {
		name, ext string
		comp      []byte
		plain     []byte
	}{
		{"gzip", ".tar.gz", gzOf(t, gzPlain), gzPlain},
		{"bzip2", ".tar.bz2", bz2, bzPlain},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv := atPaths(t, map[string][]byte{
				"/x" + c.ext:          c.comp,
				"/x.tar.sign":         detach(t, key, c.plain, true),
				"/x" + c.ext + ".asc": detach(t, key, c.comp, true),
			})
			pin, err := DigestVerifiedDecompressed(srv.URL+"/x"+c.ext,
				[]string{srv.URL + "/x.tar.sign"}, ring, "")
			if err != nil {
				t.Fatalf("DigestVerifiedDecompressed: %v", err)
			}
			if want := sha256of(c.comp); pin.SHA256 != want {
				t.Errorf("SHA256 = %s, want %s", pin.SHA256, want)
			}

			// The control for THIS format: the served bytes have their own
			// valid signature, and asking for the decompressed one must refuse
			// it. Otherwise "decompressed" could be reading the file whole.
			if _, err := DigestVerifiedDecompressed(srv.URL+"/x"+c.ext,
				[]string{srv.URL + "/x" + c.ext + ".asc"}, ring, ""); err == nil {
				t.Error("a signature over the COMPRESSED bytes was accepted as covering the decompressed stream")
			}
		})
	}
}

// ⛔ TestDecompressingDoesNotWeakenWhoSigned: the point of the whole package is
// that an unnamed key is a refusal. Decompressing changes which bytes are
// hashed and must change nothing else.
func TestDecompressingDoesNotWeakenWhoSigned(t *testing.T) {
	mine, other := testKey(t), secondKey(t)
	plain := []byte("signed by somebody the author did not name\n")
	comp := xzOf(t, plain)
	srv := atPaths(t, map[string][]byte{
		"/x.tar.xz":   comp,
		"/x.tar.sign": detach(t, other, plain, true),
	})
	url, sigs := srv.URL+"/x.tar.xz", []string{srv.URL + "/x.tar.sign"}

	// Not in the keyring at all.
	_, err := DigestVerifiedDecompressed(url, sigs, armoredPublicKey(t, mine), "")
	if err == nil {
		t.Fatal("a key outside the keyring was accepted")
	}
	// ⚠ And the refusal must NOT carry the --sig-covers hint: the bytes were
	// already the signed ones, so pointing at the other stream would send the
	// next reader to re-check what is not wrong.
	if strings.Contains(err.Error(), "--sig-covers") {
		t.Errorf("a key failure is advertised as a bytes failure:\n%v", err)
	}

	// In the keyring, but not the fingerprint named.
	ring := twoKeyRing(t, mine, other)
	want := strings.ToUpper(hex.EncodeToString(mine.PrimaryKey.Fingerprint))
	if _, err := DigestVerifiedDecompressed(url, sigs, ring, want); err == nil {
		t.Error("a signature by the other key in the ring was accepted for the named fingerprint")
	}
}

// TestOneFlippedByteIsRefused is the control go-zpkg/zpkb#492 ran against its
// own purpose-built prototype, kept here: the signature is good, the key is
// right, and the contents are not what was signed.
func TestOneFlippedByteIsRefused(t *testing.T) {
	key := testKey(t)
	signed := []byte("the bytes that were signed\n")
	served := append([]byte(nil), signed...)
	served[0] ^= 1

	srv := atPaths(t, map[string][]byte{
		"/x.tar.xz":   xzOf(t, served),
		"/x.tar.sign": detach(t, key, signed, true),
	})
	_, err := DigestVerifiedDecompressed(srv.URL+"/x.tar.xz",
		[]string{srv.URL + "/x.tar.sign"}, armoredPublicKey(t, key), "")
	if err == nil {
		t.Fatal("a signature over different contents was accepted")
	}
}

// TestCoversIsRecordedForTheServedShapeToo: the field is on every pin, not
// only the unusual one, so a reader never has to decide what an empty value
// meant.
func TestCoversIsRecordedForTheServedShapeToo(t *testing.T) {
	key := testKey(t)
	body := tinyGz(t, "ordinary")
	srv := atPaths(t, map[string][]byte{
		"/x.tar.gz":     body,
		"/x.tar.gz.asc": detach(t, key, body, true),
	})
	pin, err := DigestVerified(srv.URL+"/x.tar.gz",
		[]string{srv.URL + "/x.tar.gz.asc"}, armoredPublicKey(t, key), "")
	if err != nil {
		t.Fatal(err)
	}
	if pin.Covers != CoversServed {
		t.Errorf("Covers = %q, want %q", pin.Covers, CoversServed)
	}
}

// ⛔⛔ TestWhatCannotBeDecompressed, and the assertion that matters is the LAST
// one in each row: a decompression failure must not read as a signature
// failure. They surface from inside the same call, the advice after a bad
// signature is "do not pin this until you know who signed it", and that advice
// sends whoever reads it to audit a key when the download was truncated.
func TestWhatCannotBeDecompressed(t *testing.T) {
	// A header good enough to pass magicWrong() and broken immediately after.
	badGz := append([]byte{0x1f, 0x8b, 0xff}, bytes.Repeat([]byte{0}, 20)...)
	badXz := append([]byte{0xfd, '7', 'z', 'X', 'Z', 0x00}, bytes.Repeat([]byte{0xff}, 40)...)

	for _, c := range []struct {
		name, path string
		body       []byte
		want       []string
	}{
		{"a plain tar has nothing to decompress", "/x.tar", []byte("tar bytes, not compressed at all"),
			[]string{"is a tar", "nothing to decompress", "verify it over the bytes served"}},
		{"a zip is not a stream", "/x.zip", []byte("PK\x03\x04 and the rest"),
			[]string{"is a zip", "nothing to decompress"}},
		{"an unnamed format has no decompressor", "/x", []byte("whatever this is"),
			[]string{"does not say what archive format"}},
		{"a broken gzip is not a bad signature", "/x.tar.gz", badGz,
			[]string{"read gzip", "NOT a signature failure"}},
		{"a broken xz is not a bad signature", "/x.tar.xz", badXz,
			[]string{"read xz", "NOT a signature failure"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			key := testKey(t)
			srv := atPaths(t, map[string][]byte{
				c.path:        c.body,
				"/x.tar.sign": detach(t, key, []byte("irrelevant"), true),
			})
			_, err := DigestVerifiedDecompressed(srv.URL+c.path,
				[]string{srv.URL + "/x.tar.sign"}, armoredPublicKey(t, key), "")
			if err == nil {
				t.Fatal("accepted")
			}
			for _, want := range c.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("message does not say %q:\n%v", want, err)
				}
			}
			if strings.Contains(err.Error(), "not vouched for") {
				t.Errorf("a decompression failure is reported as a signature failure:\n%v", err)
			}
		})
	}
}

// TestDecompressorClosesWhatItOpens drives the one branch the end-to-end tests
// cannot observe: gzip's reader is an io.Closer and the other two are not, and
// the file underneath must not be closed twice. Checked directly because a
// double close is silent — os.File.Close on a closed file returns an error
// nothing here looks at.
func TestDecompressorClosesWhatItOpens(t *testing.T) {
	dir := t.TempDir()
	for _, c := range []struct {
		url    string
		body   []byte
		closer bool
	}{
		{"https://x/a.tar.gz", gzOf(t, []byte("g")), true},
		{"https://x/a.tar.xz", xzOf(t, []byte("x")), false},
	} {
		path := filepath.Join(dir, filepath.Base(c.url))
		if err := os.WriteFile(path, c.body, 0o600); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		d, err := decompressor(f, c.url)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := d.(io.Closer); ok != c.closer {
			t.Errorf("%s: io.Closer = %v, want %v", c.url, ok, c.closer)
		}
		if _, err := io.ReadAll(d); err != nil {
			t.Errorf("%s: read: %v", c.url, err)
		}
		f.Close()
	}
}
