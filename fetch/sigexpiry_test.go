package fetch

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// lapsedKey returns a key that was created three years ago with a one-year
// lifetime, so it expired two years ago, and the instant halfway through its
// valid window.
//
// ⛔ THE KEY HAS TO BE GENERATED WITH A PAST CLOCK, not merely given a short
// lifetime: an expiry is `creation + KeyLifetimeSecs`, so a key created NOW
// with a one-year life is valid for a year whatever the lifetime says. Both
// halves are needed to produce the state the fleet actually meets — a key that
// signed something and has since lapsed.
func lapsedKey(t *testing.T) (*openpgp.Entity, time.Time) {
	t.Helper()
	created := time.Now().AddDate(-3, 0, 0)
	cfg := &packet.Config{
		Time:            func() time.Time { return created },
		KeyLifetimeSecs: 365 * 24 * 60 * 60,
	}
	e, err := openpgp.NewEntity("Lapsed Author", "key expired two years ago", "lapsed@upstream.example", cfg)
	if err != nil {
		t.Fatal(err)
	}
	return e, created.AddDate(0, 6, 0)
}

// signAt makes a detached signature dated at a chosen instant.
func signAt(t *testing.T, e *openpgp.Entity, body []byte, when time.Time) []byte {
	t.Helper()
	var buf bytes.Buffer
	cfg := &packet.Config{Time: func() time.Time { return when }}
	if err := openpgp.ArmoredDetachSign(&buf, e, bytes.NewReader(body), cfg); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// ⛔⛔ THE DEFECT, AND THIS IS THE TEST THAT WOULD HAVE CAUGHT IT.
// go-zpkg/zpkb#484: a signature made while the key was valid was refused once
// the key lapsed, because expiry was judged at time.Now() rather than at the
// signature's creation instant.
//
// Three real instances before this test existed — gnu.org/wget 1.25.0, the
// second case the issue records, and x.org/libX11 1.8.14, whose signature by
// Alan Coopersmith is what sent it to be fixed rather than worked around. In
// every one `gpg --verify` exits 0 with "Good signature" plus a NOTE about the
// expiry, and `sourcepin` exited 1 with "openpgp: key expired".
//
// ⚠ The warrant is what is being judged: a signature justifies WRITING a digest
// once, and a warrant issued in 2024 by a key valid in 2024 does not stop being
// one because the key lapsed in 2025.
func TestASignatureMadeWhileTheKeyWasValidSurvivesTheKeyLapsing(t *testing.T) {
	key, inWindow := lapsedKey(t)
	body := tinyGz(t, "the source")
	sig := signAt(t, key, body, inWindow)
	srv := signedServer(t, body, map[string][]byte{"/x.tar.gz.asc": sig})

	pin, err := DigestVerified(srv.URL+"/x.tar.gz",
		[]string{srv.URL + "/x.tar.gz.asc"}, armoredPublicKey(t, key), "")
	if err != nil {
		t.Fatalf("a signature made inside the key's valid window was refused: %v", err)
	}
	if !strings.Contains(pin.Identity, "lapsed@upstream.example") {
		t.Errorf("identity = %q", pin.Identity)
	}
	// ⭐ AND THE INSTANT IS REPORTED, because "verified" now means "the key was
	// valid when it signed" and a reader of a pull request cannot tell that
	// from "the key is valid now" unless the date is printed.
	if pin.SignedAt.IsZero() {
		t.Error("SignedAt is zero: the clock the expiry was judged at is not reported")
	}
	if d := pin.SignedAt.Sub(inWindow); d > time.Minute || d < -time.Minute {
		t.Errorf("SignedAt = %s, want the signature's own instant %s", pin.SignedAt, inWindow)
	}
}

// ⛔⛔ THE CONTROL THAT KEEPS THE FIX FROM BEING A HOLE: THE EXPIRY CHECK STILL
// RUNS, AND ONLY THE CLOCK MOVED. The same signature and the same key, judged
// at time.Now() — the old behaviour — must still be REFUSED for expiry. If
// this passed, the change would be indistinguishable from "ignore expiry".
//
// ⚠ IT IS WRITTEN THIS WAY BECAUSE THE OBVIOUS FIXTURE CANNOT BE BUILT.
// Signing after the key expired was the first attempt, and go-crypto refuses:
// `openpgp: invalid argument: no valid signing keys`. The library will not
// produce a signature from a key outside its own validity window, so "a
// signature made after expiry" is not a thing an honest test can hand the
// verifier — and a test that cannot be built must not be faked. What CAN be
// demonstrated is the half that matters: the check is live, and the clock is
// the only thing this change touched.
func TestTheExpiryCheckStillRunsAndOnlyTheClockMoved(t *testing.T) {
	key, inWindow := lapsedKey(t)
	body := tinyGz(t, "the source")
	sig := signAt(t, key, body, inWindow)

	keys, _, err := readKeyring(armoredPublicKey(t, key), "")
	if err != nil {
		t.Fatal(err)
	}

	// The old clock: time.Now(), which a nil config selects. The key lapsed a
	// year ago, so this must fail — and fail ON THE EXPIRY.
	_, err = openpgp.CheckArmoredDetachedSignature(keys, bytes.NewReader(body), bytes.NewReader(sig), nil)
	if err == nil {
		t.Fatal("judged at time.Now() the lapsed key was accepted — then the expiry check is not running at all, and this change is not about a clock")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("at time.Now() the failure was %v; want the expiry", err)
	}

	// The new clock: the signature's own instant, which is inside the window.
	cfg, _, err := sigTimeConfig(sig)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openpgp.CheckArmoredDetachedSignature(keys, bytes.NewReader(body), bytes.NewReader(sig), cfg); err != nil {
		t.Fatalf("judged at the signature's instant the same signature failed: %v", err)
	}
}

// ⛔ A SIGNATURE DATED IN THE FUTURE IS REFUSED, and it is the one claim the
// signature's own clock cannot be trusted for. Everything else here trusts
// that clock; a time that has not happened would let a key's expiry be evaded
// indefinitely rather than only back to when the key was valid.
func TestASignatureDatedInTheFutureIsRefused(t *testing.T) {
	key := testKey(t)
	body := tinyGz(t, "the source")
	sig := signAt(t, key, body, time.Now().Add(48*time.Hour))
	srv := signedServer(t, body, map[string][]byte{"/x.tar.gz.asc": sig})

	_, err := DigestVerified(srv.URL+"/x.tar.gz",
		[]string{srv.URL + "/x.tar.gz.asc"}, armoredPublicKey(t, key), "")
	if err == nil {
		t.Fatal("a signature dated two days in the future was accepted")
	}
	if !strings.Contains(err.Error(), "future") {
		t.Errorf("error = %v; want it to say the time has not happened", err)
	}
}

// ⚠ AND AN HOUR OF SKEW IS ALLOWED, because a release machine's clock and this
// one's are not the same clock. Without this the fix would refuse a signature
// made minutes ago on a host running slightly fast — a refusal with no
// security value and a very confusing message.
func TestAnHourOfClockSkewIsNotTreatedAsTheFuture(t *testing.T) {
	key := testKey(t)
	body := tinyGz(t, "the source")
	sig := signAt(t, key, body, time.Now().Add(20*time.Minute))
	srv := signedServer(t, body, map[string][]byte{"/x.tar.gz.asc": sig})

	if _, err := DigestVerified(srv.URL+"/x.tar.gz",
		[]string{srv.URL + "/x.tar.gz.asc"}, armoredPublicKey(t, key), ""); err != nil {
		t.Fatalf("twenty minutes of skew was refused: %v", err)
	}
}

// ⭐ THE RULES ARE TESTED AGAINST LITERALS TOO, not only end to end. The two
// end-to-end tests above each cost a keypair, which is the slowest thing in
// this package; these cost nothing and pin the shape of the decision.
func TestSigTimeConfigRules(t *testing.T) {
	// ⚠ THE LAPSED KEY, NOT `testKey`, AND THE REASON IS A MEASUREMENT RATHER
	// THAN A PREFERENCE: go-crypto refuses to sign at any instant before the
	// key was created — `openpgp: invalid argument: no valid signing keys` —
	// and `testKey` is created when the first test asks for it. Even one minute
	// in the past was refused. `lapsedKey` exists precisely to have a KNOWN
	// past window, which is what an assertion about carrying a past clock needs.
	key, when := lapsedKey(t)
	body := []byte("x")

	cfg, got, err := sigTimeConfig(signAt(t, key, body, when))
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil || cfg.Time == nil {
		t.Fatal("no config: the verifier would fall back to time.Now()")
	}
	if !cfg.Time().Equal(got) || got.Sub(when).Abs() > time.Minute {
		t.Errorf("config clock = %s, reported %s, want %s", cfg.Time(), got, when)
	}

	// ⛔ A NIL CONFIG IS THE STRICT BEHAVIOUR, so an undated signature must
	// produce one rather than a zero-time clock — a clock at the Unix epoch
	// would make every key "not yet valid" instead of judging it now.
	cfg, got, err = sigTimeConfig([]byte("not a signature at all"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg != nil || !got.IsZero() {
		t.Errorf("undated/unparseable → cfg=%v t=%s; want nil and zero, which means time.Now()", cfg, got)
	}
}

// ⛔⛔ A CORRUPT SIGNATURE FALLS BACK TO THE STRICT CLOCK AND THE *VERIFIER*
// REPORTS IT — one authority, not two.
//
// ⚠ THIS TEST IS THE REASON THE CODE READS THAT WAY. It was written to prove
// the opposite: a comment I had put in `signatureCreationTime` claimed corrupt
// armour was reported as an error. The test failed, because `armor.Decode`
// reads only the HEADER — bad base64 surfaces later, inside packet.NewReader,
// and reached the fallback arm anyway. The comment was wrong, so the comment
// went; the behaviour is now stated and asserted instead of claimed.
//
// What matters is that the BROKEN FILE still produces a refusal, from the
// place that is actually checking the signature.
func TestACorruptSignatureFallsBackAndTheVerifierIsTheOneToRefuse(t *testing.T) {
	bad := []byte("-----BEGIN PGP SIGNATURE-----\n\nnot base64 at all !!!\n-----END PGP SIGNATURE-----\n")

	cfg, got, err := sigTimeConfig(bad)
	if err != nil {
		t.Fatalf("sigTimeConfig gave its own verdict on a broken file: %v", err)
	}
	if cfg != nil || !got.IsZero() {
		t.Errorf("corrupt → cfg=%v t=%s; want nil and zero, i.e. the strict clock", cfg, got)
	}

	// ⭐ AND THE OTHER CORRUPTION, WHICH FAILS AT A DIFFERENT LAYER: an armour
	// header with NOTHING AFTER IT. That is where `armor.Decode` itself errors
	// — it reads the header and then hits EOF — whereas bad base64 gets past
	// Decode and fails later in the packet reader. Two inputs, two layers, one
	// behaviour: fall back and let the verifier speak.
	truncated := []byte("-----BEGIN PGP SIGNATURE-----")
	cfg, got, err = sigTimeConfig(truncated)
	if err != nil {
		t.Fatalf("truncated armour gave its own verdict: %v", err)
	}
	if cfg != nil || !got.IsZero() {
		t.Errorf("truncated → cfg=%v t=%s; want nil and zero", cfg, got)
	}

	// And end to end: the file is still refused, by the verifier.
	key := testKey(t)
	body := tinyGz(t, "the source")
	srv := signedServer(t, body, map[string][]byte{"/x.tar.gz.asc": bad})
	if _, err := DigestVerified(srv.URL+"/x.tar.gz",
		[]string{srv.URL + "/x.tar.gz.asc"}, armoredPublicKey(t, key), ""); err == nil {
		t.Fatal("a corrupt signature was accepted")
	}
}

// ⚠ AND A WELL-FORMED PACKET STREAM WITH NO SIGNATURE IN IT falls back to the
// strict clock rather than erroring. This is the EOF arm: the bytes parsed
// fine and simply held no signature packet — a public key block, say — so
// there is no creation time to use and nothing is wrong with the file either.
// The verifier downstream is the authority on whether it is a usable
// signature.
func TestAPacketStreamWithNoSignatureFallsBackToTheStrictClock(t *testing.T) {
	key := testKey(t)
	cfg, got, err := sigTimeConfig(armoredPublicKey(t, key))
	if err != nil {
		t.Fatalf("a public key block is not an error here: %v", err)
	}
	if cfg != nil || !got.IsZero() {
		t.Errorf("no signature packet → cfg=%v t=%s; want nil and zero", cfg, got)
	}
}
