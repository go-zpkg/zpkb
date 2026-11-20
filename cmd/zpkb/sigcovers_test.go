package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/go-zpkg/zpkb/fetch"
)

// --sig-covers (go-zpkg/zpkb#492), and the printing of the two facts a reader
// of the recipe cannot get any other way: when the signature was made, and
// which bytes it covered.

// coveredPin drives --sig with BOTH verifiers stubbed, and reports which one
// was called with which candidates.
//
// ⛔ BOTH, BECAUSE STUBBING ONE PROVES NOTHING. A dispatch test that replaces
// only the verifier it expects passes just as well when the flag is ignored —
// the other call would go to the network, the test would be slow and red for a
// reason that looks like flake, and on a machine with no network it would be
// red for a third reason. Each stub records itself, and the assertion is which
// one ran AND that the other did not.
type callRecord struct {
	served, decompressed int
	cands                []string
}

func coveredPin(t *testing.T, pin fetch.SourcePin, args ...string) (int, string, string, *callRecord) {
	t.Helper()
	var rec callRecord
	wasS, wasD, wasK := fetchVerified, fetchVerifiedDecompressed, readKeyFile
	fetchVerified = func(_ string, cands []string, _ []byte, _ string) (fetch.SourcePin, error) {
		rec.served++
		rec.cands = cands
		return pin, nil
	}
	fetchVerifiedDecompressed = func(_ string, cands []string, _ []byte, _ string) (fetch.SourcePin, error) {
		rec.decompressed++
		rec.cands = cands
		return pin, nil
	}
	readKeyFile = func(string) ([]byte, error) { return []byte("key"), nil }
	t.Cleanup(func() { fetchVerified, fetchVerifiedDecompressed, readKeyFile = wasS, wasD, wasK })
	var out, errb bytes.Buffer
	rc := runSourcePin(args, &out, &errb)
	return rc, out.String(), errb.String(), &rec
}

func signedArgs(extra ...string) []string {
	base := []string{"--sig", "auto", "--key", "k.asc", "--key-source", "their release page"}
	return append(append(base, extra...), "https://x/linux-7.2.15.tar.xz")
}

// ⛔⛔ TestSigCoversDispatchesAndNothingElseRuns is the flag's whole contract.
func TestSigCoversDispatchesAndNothingElseRuns(t *testing.T) {
	for _, c := range []struct {
		name               string
		extra              []string
		served, decomposed int
	}{
		{"the default is today's behaviour", nil, 1, 0},
		{"served, named explicitly", []string{"--sig-covers", "served"}, 1, 0},
		{"decompressed", []string{"--sig-covers", "decompressed"}, 0, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			rc, _, errb, rec := coveredPin(t, aPin, signedArgs(c.extra...)...)
			if rc != 0 {
				t.Fatalf("rc = %d, stderr = %q", rc, errb)
			}
			if rec.served != c.served || rec.decompressed != c.decomposed {
				t.Errorf("served=%d decompressed=%d, want %d and %d",
					rec.served, rec.decompressed, c.served, c.decomposed)
			}
		})
	}
}

// ⛔⛔ TestSigCoversRefusesAValueItDoesNotKnow: a misspelling must not fall
// back to the default. It would verify the served bytes and print a pin whose
// provenance says `covers served` — the one wrong answer this flag exists to
// stop somebody writing into a recipe by hand, and indistinguishable from the
// right one afterwards.
func TestSigCoversRefusesAValueItDoesNotKnow(t *testing.T) {
	for _, bad := range []string{"decompresed", "DECOMPRESSED", "uncompressed", "yes", "tar"} {
		rc, out, errb, rec := coveredPin(t, aPin, signedArgs("--sig-covers", bad)...)
		if rc != 2 {
			t.Errorf("%q: rc = %d, want 2", bad, rc)
		}
		if rec.served+rec.decompressed != 0 {
			t.Errorf("%q: a verifier ran anyway", bad)
		}
		if strings.Contains(out, "sha256") {
			t.Errorf("%q: a digest was printed anyway:\n%s", bad, out)
		}
		// The message has to name the two values, because the whole failure is
		// that the author did not know which spelling to use.
		for _, want := range []string{bad, `"served"`, `"decompressed"`} {
			if !strings.Contains(errb, want) {
				t.Errorf("%q: refusal does not mention %s: %q", bad, want, errb)
			}
		}
	}
}

// And the inverse, matching the other three flags: it means nothing without
// --sig, so saying so beats accepting it and ignoring it.
func TestSigCoversWithoutSigIsAUsageError(t *testing.T) {
	rc, _, errb, _ := coveredPin(t, aPin, "--sig-covers", "decompressed", "https://x/y.tar.xz")
	if rc != 2 || !strings.Contains(errb, "only mean something with --sig") {
		t.Errorf("rc=%d %q", rc, errb)
	}
	if !strings.Contains(errb, "--sig-covers") {
		t.Errorf("the refusal does not name the flag that caused it: %q", errb)
	}
}

// ⛔⛔ TestAutoStripsTheCompressionSuffix: `--sig auto` could not find
// kernel.org's signature even in principle, and this is why. go-zpkg/zpkb#492
// measured the four names: linux-7.2.15.tar.xz.asc 404, .tar.xz.sig 404,
// .tar.xz.sign 404, linux-7.2.15.tar.sign 200. A signature names the bytes it
// covers, so one over the decompressed archive is published under the
// decompressed name.
func TestAutoStripsTheCompressionSuffix(t *testing.T) {
	for _, c := range []struct {
		url  string
		want []string
	}{
		{"https://x/linux-7.2.15.tar.xz", []string{
			"https://x/linux-7.2.15.tar.sign",
			"https://x/linux-7.2.15.tar.asc",
			"https://x/linux-7.2.15.tar.sig"}},
		{"https://x/a.tar.gz", []string{
			"https://x/a.tar.sign", "https://x/a.tar.asc", "https://x/a.tar.sig"}},
		{"https://x/a.tar.bz2", []string{
			"https://x/a.tar.sign", "https://x/a.tar.asc", "https://x/a.tar.sig"}},
		// Already uncompressed: there is nothing to strip, and the names are
		// still the decompressed shape's. fetch refuses this URL later — a
		// plain .tar has nothing to decompress — but the candidate list is not
		// where that is decided.
		{"https://x/a.tar", []string{
			"https://x/a.tar.sign", "https://x/a.tar.asc", "https://x/a.tar.sig"}},
	} {
		got := autoCandidates(c.url, fetch.CoversDecompressed)
		if strings.Join(got, " ") != strings.Join(c.want, " ") {
			t.Errorf("%s: candidates = %v, want %v", c.url, got, c.want)
		}
	}
	// ⚠ THE CONTROL: the served shape is unchanged. This function is on the
	// path of every `--sig auto` invocation, and the three recipes already
	// written against it must keep resolving the same two names.
	if got := autoCandidates("https://x/a.tar.gz", fetch.CoversServed); strings.Join(got, " ") !=
		"https://x/a.tar.gz.asc https://x/a.tar.gz.sig" {
		t.Errorf("the served shape changed: %v", got)
	}
}

// ⛔⛔ TestTheSignatureInstantIsPrinted closes a gap go-zpkg/zpkb#506 left
// open: it added SourcePin.SignedAt with the comment "it is reported because
// it is now part of the verdict … a reader of a pull request cannot tell those
// apart unless the instant is printed", and NOTHING printed it. Its test
// asserted the field was populated, which is a different claim. "Verified" now
// means "the key was valid WHEN IT SIGNED", so the clock belongs in the output
// and in the block that gets pasted into the recipe.
func TestTheSignatureInstantIsPrinted(t *testing.T) {
	signed := aPin
	signed.SignedAt = time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	rc, out, errb, _ := coveredPin(t, signed, signedArgs()...)
	if rc != 0 {
		t.Fatalf("rc = %d, stderr = %q", rc, errb)
	}
	const instant = "2024-06-01T12:00:00Z"
	if !strings.Contains(out, instant) {
		t.Errorf("the signature's instant is not printed:\n%s", out)
	}
	// ⛔ AND IT IS IN THE PASTED BLOCK, NOT ONLY ABOVE IT. The terminal lines
	// are read once by whoever ran the command; the provenance block is what
	// the next reader of the recipe has. A verdict that survives only in a
	// scrollback was not recorded.
	block := out[strings.Index(out, "provenance {"):]
	if !strings.Contains(block, instant) {
		t.Errorf("the instant is not in the provenance block:\n%s", block)
	}
	if !strings.Contains(block, "expiry was judged at") {
		t.Errorf("the block does not say what the instant IS:\n%s", block)
	}

	// ⚠ The other arm: a signature with no creation time was judged at
	// time.Now(), which is the strict clock. Silence there would read as "the
	// instant above", and there is no instant above.
	_, out, _, _ = coveredPin(t, aPin, signedArgs()...)
	if !strings.Contains(out, "no creation time") || !strings.Contains(out, "strict clock") {
		t.Errorf("an undated signature does not say which clock was used:\n%s", out)
	}
	if strings.Contains(out[strings.Index(out, "provenance {"):], "signed at") {
		t.Error("the provenance block claims an instant the signature did not carry")
	}
}

// TestTheProvenanceBlockSaysWhichBytes: the digest and the warrant no longer
// describe the same bytes, and the recipe is where that has to be legible.
func TestTheProvenanceBlockSaysWhichBytes(t *testing.T) {
	dec := aPin
	dec.Covers = fetch.CoversDecompressed
	rc, out, errb, _ := coveredPin(t, dec, signedArgs("--sig-covers", "decompressed")...)
	if rc != 0 {
		t.Fatalf("rc = %d, stderr = %q", rc, errb)
	}
	for _, want := range []string{"covers", "DECOMPRESSED archive", "COMPRESSED file's"} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not say %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out[strings.Index(out, "provenance {"):], "DECOMPRESSED") {
		t.Errorf("the pasted block does not say which bytes were checked:\n%s", out)
	}

	// ⚠ THE CONTROL, and it is why the line is conditional. A line on every
	// invocation repeating the default trains the eye to skip the line that
	// matters, so the served shape must stay silent about it.
	_, out, _, _ = coveredPin(t, aPin, signedArgs()...)
	if strings.Contains(out, "DECOMPRESSED") {
		t.Errorf("the served shape talks about decompression:\n%s", out)
	}
}

// ⛔⛔ TestARefreshedKeySaysWhichInstantItWasJudgedAt (go-zpkg/zpkb#512).
// The output said "signed at X, and that is the instant the key's expiry was
// judged at" unconditionally — and on gnu.org/libidn2 2.3.8 printed exactly
// that while the checks had run at the key's refresh, fourteen months later.
// When the two differ, both are printed, in the terminal and in the block that
// survives into the recipe.
func TestARefreshedKeySaysWhichInstantItWasJudgedAt(t *testing.T) {
	refreshed := aPin
	refreshed.SignedAt = time.Date(2025, 3, 8, 23, 10, 44, 0, time.UTC)
	refreshed.JudgedAt = time.Date(2026, 4, 17, 8, 55, 45, 0, time.UTC)
	rc, out, errb, _ := coveredPin(t, refreshed, signedArgs()...)
	if rc != 0 {
		t.Fatalf("rc = %d, stderr = %q", rc, errb)
	}
	if strings.Contains(out, "and that is the instant the key's expiry was judged at") {
		t.Errorf("the output claims the signature's own instant was the one judged:\n%s", out)
	}
	for _, want := range []string{"2025-03-08T23:10:44Z", "judged at 2026-04-17T08:55:45Z", "refreshed after it signed"} {
		if !strings.Contains(out, want) {
			t.Errorf("the output does not say %q:\n%s", want, out)
		}
	}
	block := out[strings.Index(out, "provenance {"):]
	if !strings.Contains(block, "judged at  2026-04-17T08:55:45Z") {
		t.Errorf("the pasted block does not carry the judged instant:\n%s", block)
	}

	// ⚠ THE CONTROL: the same instant twice keeps the old sentence — an
	// unrefreshed key must read exactly as it did before #512.
	same := aPin
	same.SignedAt = refreshed.SignedAt
	same.JudgedAt = refreshed.SignedAt
	_, out, _, _ = coveredPin(t, same, signedArgs()...)
	if !strings.Contains(out, "and that is the instant the key's expiry was judged at") ||
		strings.Contains(out, "judged at 20") {
		t.Errorf("an unrefreshed key's output changed:\n%s", out)
	}
}
