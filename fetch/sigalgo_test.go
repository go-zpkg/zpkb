package fetch

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// go-zpkg/zpkb#482: the refusal must name the cause it met. The three states
// are separated by reading the signature's issuer against the keyring, so they
// are tested against a keyring rather than through a server where possible.

// ringOf is the keyring DigestVerified would build, so a test and the
// production path classify the same object.
func ringOf(t *testing.T, e *openpgp.Entity) openpgp.EntityList {
	t.Helper()
	keys, _, err := readKeyring(armoredPublicKey(t, e), "")
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

// unflag reproduces the ONE property that refuses gnu.org/help2man: a
// self-signature with no key-flags subpacket. Measured on the real key —
// Brendan O'Dea's, self-signed 2001-06-19 — where FlagsValid is false,
// KeysById answers 1 and KeysByIdUsage(KeyFlagSign) answers 0.
//
// ⛔ PATCHED IN MEMORY BECAUSE IT CANNOT BE BUILT. go-crypto emits key flags on
// every key it generates and refuses to emit a SHA-1 signature at all
// (`ArmoredDetachSign` answers "invalid argument: invalid hash function"), so
// neither half of the real case can be produced by the library. The real case
// is measured in this package's doc comment and in the pull request; this
// drives the branch.
func unflag(t *testing.T, keys openpgp.EntityList, selfSigned time.Time) {
	t.Helper()
	patched := 0
	for _, e := range keys {
		for _, id := range e.Identities {
			if id.SelfSignature == nil {
				continue
			}
			id.SelfSignature.FlagsValid = false
			id.SelfSignature.FlagSign = false
			id.SelfSignature.CreationTime = selfSigned
			patched++
		}
	}
	if patched == 0 {
		t.Fatal("no self-signature to patch: the fixture cannot reach the branch")
	}
}

// ⛔⛔ TestAKeyOlderThanTheFlagIsNamedAsSuch is go-zpkg/zpkb#482's real cause,
// which the issue itself misdiagnosed as DSA/SHA-1 from a packet dump.
func TestAKeyOlderThanTheFlagIsNamedAsSuch(t *testing.T) {
	key := testKey(t)
	body := tinyGz(t, "the source")
	sig := detach(t, key, body, true)
	keys := ringOf(t, key)

	// The control FIRST, so the fixture is known to be in the other state
	// before it is moved: with flags, this is a signing key.
	if d := classifyDeclined(sig, keys); d.kind != declinedWithASigningKey {
		t.Fatalf("before patching, kind = %d, want declinedWithASigningKey", d.kind)
	}

	unflag(t, keys, time.Date(2001, 6, 19, 2, 51, 8, 0, time.UTC))
	d := classifyDeclined(sig, keys)
	if d.kind != declinedNotSignCapable {
		t.Fatalf("kind = %d, want declinedNotSignCapable", d.kind)
	}

	msg := d.because(CoversServed)
	for _, want := range []string{
		"THE KEY IS PRESENT",
		"no key-flags subpacket",
		"2001-06-19",      // the SELF-signature's date, not the signature's
		"gpg infers",      // so nobody audits a keyring that is fine
		"policy decision", // the verdict is deliberately left open
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("the clause does not say %q:\n%s", want, msg)
		}
	}
	// ⛔ AND NOT A WORD ABOUT BYTES. The bytes were never in question, and the
	// unconditional --sig-covers hint from go-zpkg/zpkb#507 said otherwise on
	// exactly this case.
	if strings.Contains(msg, "--sig-covers") {
		t.Errorf("a flagless key is advertised as a bytes problem:\n%s", msg)
	}
}

// ⚠ TestTheSelfSignatureDateIsTheKeysNotTheSignatures: the two are twenty-one
// years apart in the real case, and the message says "its self-signature
// (made …)". Taking the date off the signature in hand reads as sourced and is
// a sentence about the wrong packet — it was written that way once.
func TestTheSelfSignatureDateIsTheKeysNotTheSignatures(t *testing.T) {
	key := testKey(t)
	body := tinyGz(t, "the source")
	keys := ringOf(t, key)
	unflag(t, keys, time.Date(2001, 6, 19, 0, 0, 0, 0, time.UTC))

	// The detached signature is made NOW, so a message carrying this year is
	// quoting the wrong packet.
	d := classifyDeclined(detach(t, key, body, true), keys)
	msg := d.because(CoversServed)
	if !strings.Contains(msg, "2001-06-19") {
		t.Errorf("the self-signature's date is absent:\n%s", msg)
	}
	if now := time.Now().UTC().Format("2006-01-02"); strings.Contains(msg, now) {
		t.Errorf("the message carries the DATA signature's date %s:\n%s", now, msg)
	}
}

// TestTheBytesHintIsOfferedOnlyWhereBytesCanBeTheProblem.
func TestTheBytesHintIsOfferedOnlyWhereBytesCanBeTheProblem(t *testing.T) {
	key := testKey(t)
	body := tinyGz(t, "the source")
	keys := ringOf(t, key)
	d := classifyDeclined(detach(t, key, body, true), keys)
	if d.kind != declinedWithASigningKey {
		t.Fatalf("kind = %d, want declinedWithASigningKey", d.kind)
	}
	if got := d.because(CoversServed); !strings.Contains(got, "--sig-covers decompressed") {
		t.Errorf("the served shape does not offer the other stream:\n%s", got)
	}
	// ⚠ And not when the other stream was ALREADY the one checked: there is no
	// third stream to suggest, and suggesting one would be noise over a real
	// signature failure.
	if got := d.because(CoversDecompressed); got != "" {
		t.Errorf("the decompressed shape still advertises a flag: %q", got)
	}
}

// TestWhatCannotBeClassified: every unreadable shape falls into the state that
// adds no claim, because the verifier has already spoken and inventing a
// second opinion here is what this file exists to prevent.
func TestWhatCannotBeClassified(t *testing.T) {
	keys := ringOf(t, testKey(t))
	for _, c := range []struct {
		name string
		sig  []byte
	}{
		{"armour that is not a signature", []byte("-----BEGIN PGP SIGNATURE-----\nnot base64 at all\n")},
		{"an empty file", nil},
		{"rubbish", []byte("\x00\x01\x02")},
		{"a packet stream with no signature in it", binaryPublicKey(t, testKey(t))},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := classifyDeclined(c.sig, keys)
			if d.kind != declinedWithASigningKey {
				t.Errorf("kind = %d, want the state that claims nothing", d.kind)
			}
			if got := d.because(CoversDecompressed); got != "" {
				t.Errorf("a claim was made about an unreadable signature: %q", got)
			}
		})
	}
}

// TestSelfSigAgeWhenThereIsNoDate covers the arm no fixture reaches through
// classifyDeclined: a key found, with a self-signature carrying no creation
// time. The message must not print an empty parenthesis.
func TestSelfSigAgeWhenThereIsNoDate(t *testing.T) {
	for _, d := range []declined{
		{kind: declinedNotSignCapable, selfSig: nil},
		{kind: declinedNotSignCapable, selfSig: &packet.Signature{}},
	} {
		if got := d.selfSigAge(); !strings.Contains(got, "could not be read") {
			t.Errorf("selfSigAge() = %q, want it to say the date is unknown", got)
		}
	}
}

// TestSigIssuerReadsBothEncodings: a `.sig` is binary and a `.asc` armoured,
// and the issuer has to be readable from either or the classification silently
// degrades to "claims nothing" for half the pantry.
func TestSigIssuerReadsBothEncodings(t *testing.T) {
	key := testKey(t)
	body := tinyGz(t, "the source")
	for _, armoured := range []bool{true, false} {
		s := sigIssuer(detach(t, key, body, armoured))
		if s == nil || s.IssuerKeyId == nil {
			t.Fatalf("armoured=%v: no issuer read", armoured)
		}
		if *s.IssuerKeyId != key.PrimaryKey.KeyId {
			t.Errorf("armoured=%v: issuer = %016X, want %016X",
				armoured, *s.IssuerKeyId, key.PrimaryKey.KeyId)
		}
	}
	// A truncated armour body: armor.Decode reads only the header, so this
	// fails inside the packet reader and must come back nil rather than panic.
	if s := sigIssuer([]byte("-----BEGIN PGP SIGNATURE-----\n\nAAAA\n-----END PGP SIGNATURE-----\n")); s != nil {
		t.Error("a truncated armour body produced an issuer")
	}
	if s := sigIssuer(bytes.Repeat([]byte{0xc2, 0x01, 0x00}, 3)); s != nil {
		t.Error("a malformed signature packet produced an issuer")
	}
}
