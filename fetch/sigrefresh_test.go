package fetch

import (
	"errors"
	"strings"
	"testing"
	"time"

	pgperrors "github.com/ProtonMail/go-crypto/openpgp/errors"
)

// go-zpkg/zpkb#512: a key refreshed after it signed is judged at its newest
// self-signature, because go-crypto counts a signature created after the
// instant judged as expired (packet/signature.go:762-765).
//
// ⚠ DRIVEN ON AN IN-MEMORY KEYRING, as go-zpkg/zpkb#508's flagless-key test
// was: go-crypto will not sign at an instant before the signing key exists, so
// a "signed, then refreshed" key cannot be produced through the library. The
// end-to-end evidence is gnu.org/libidn2 2.3.8, measured in the pull request.

func TestTheClockMovesToARefreshNewerThanTheSignature(t *testing.T) {
	key := testKey(t)
	sig := detach(t, key, tinyGz(t, "x"), true)
	keys := ringOf(t, key)

	selfSig, _ := keys[0].PrimarySelfSignature()
	refresh := selfSig.CreationTime
	signedAt := refresh.Add(-400 * 24 * time.Hour) // signed long before the refresh
	now := refresh.Add(time.Hour)

	if got := refreshedClock(signedAt, sig, keys, now); !got.Equal(refresh) {
		t.Errorf("clock = %s, want the refresh %s", got, refresh)
	}
	// ⚠ THE CONTROL: with no refresh after the signature, #484's clock stands.
	later := refresh.Add(30 * time.Minute)
	if got := refreshedClock(later, sig, keys, now); !got.Equal(later) {
		t.Errorf("clock = %s, want the signature's own %s when nothing is newer", got, later)
	}
}

// ⛔ TestARefreshDatedInTheFutureDoesNotCarryTheClock: the clock is capped at
// the present, so a self-signature from the future cannot move every check
// forward to an instant that has not happened.
func TestARefreshDatedInTheFutureDoesNotCarryTheClock(t *testing.T) {
	key := testKey(t)
	sig := detach(t, key, tinyGz(t, "x"), true)
	keys := ringOf(t, key)
	selfSig, _ := keys[0].PrimarySelfSignature()
	now := selfSig.CreationTime.Add(-time.Hour) // the "present" is before the self-signature
	if got := refreshedClock(now.Add(-48*time.Hour), sig, keys, now); !got.Equal(now) {
		t.Errorf("clock = %s, want it capped at the present %s", got, now)
	}
}

// TestASubkeyBindingNewerThanThePrimaryMovesTheClock: for a signature made by
// a subkey, read.go:591 checks the binding and its cross-signature too, so
// those count as well. The fixture's key signs with a subkey.
func TestASubkeyBindingNewerThanThePrimaryMovesTheClock(t *testing.T) {
	key := testKey(t)
	sig := detach(t, key, tinyGz(t, "x"), true)
	keys := ringOf(t, key)
	s := sigIssuer(sig)
	found := keys.KeysById(*s.IssuerKeyId)
	if len(found) == 0 || found[0].SelfSignature == nil {
		t.Skip("the fixture key signs with its primary; no binding to move")
	}
	binding := found[0].SelfSignature
	bumped := binding.CreationTime.Add(2 * time.Hour)
	binding.CreationTime = bumped
	now := bumped.Add(time.Hour)
	if got := refreshedClock(bumped.Add(-24*time.Hour), sig, keys, now); !got.Equal(bumped) {
		t.Errorf("clock = %s, want the binding's %s", got, bumped)
	}
}

// ⛔⛔ TestTheClockNeverDropsBelowTheSignaturesOwnInstant is the regression
// go-zpkg/zpkb#484's own skew test caught in the first version of this: a
// signature dated twenty minutes ahead — allowed, an hour of skew is — was
// judged at the PRESENT, before its own creation, and go-crypto counted the
// data signature itself as created after now.
func TestTheClockNeverDropsBelowTheSignaturesOwnInstant(t *testing.T) {
	key := testKey(t)
	sig := detach(t, key, tinyGz(t, "x"), true)
	keys := ringOf(t, key)
	selfSig, _ := keys[0].PrimarySelfSignature()
	now := selfSig.CreationTime.Add(time.Hour)
	ahead := now.Add(20 * time.Minute)
	if got := refreshedClock(ahead, sig, keys, now); !got.Equal(ahead) {
		t.Errorf("clock = %s, want the signature's own %s, not the present %s", got, ahead, now)
	}
}

func TestAnUnreadableSignatureKeepsTheSignaturesClock(t *testing.T) {
	keys := ringOf(t, testKey(t))
	at := time.Date(2025, 3, 8, 0, 0, 0, 0, time.UTC)
	if got := refreshedClock(at, []byte("not a signature"), keys, at.Add(time.Hour)); !got.Equal(at) {
		t.Errorf("clock = %s, want %s unchanged", got, at)
	}
}

// TestTheRefusalCauseTakesExpiryFirst drives every branch of refusalCause:
// expiry wins over the keyring states, and otherwise the three states keep
// their go-zpkg/zpkb#508 leads.
func TestTheRefusalCauseTakesExpiryFirst(t *testing.T) {
	at := time.Date(2025, 3, 8, 0, 0, 0, 0, time.UTC)
	signing := declined{kind: declinedWithASigningKey}
	lead, why := refusalCause(pgperrors.ErrKeyExpired, signing, CoversServed, at, at)
	if strings.Contains(lead, "WHO") || !strings.Contains(why, "EXPIRY") || strings.Contains(why, "--sig-covers") {
		t.Errorf("an expiry with a signing key: lead=%q why=%q", lead, why)
	}
	other := errors.New("RSA verification failure")
	lead, why = refusalCause(other, signing, CoversServed, at, at)
	if !strings.Contains(lead, "WHO") || !strings.Contains(why, "--sig-covers") {
		t.Errorf("a bytes failure lost its hint: lead=%q why=%q", lead, why)
	}
	lead, _ = refusalCause(other, declined{kind: declinedUnknownIssuer, sig: sigIssuer(detach(t, testKey(t), tinyGz(t, "x"), true))}, CoversServed, at, at)
	if strings.Contains(lead, "WHO") {
		t.Errorf("an unknown issuer kept the WHO lead: %q", lead)
	}
}

// ⛔ TestAnExpiryIsNamedAsSuch: it used to fall into the "key present and may
// sign" arm and get the --sig-covers BYTES hint — on gnu.org/libidn2 2.3.8.
func TestAnExpiryIsNamedAsSuch(t *testing.T) {
	signed := time.Date(2025, 3, 8, 23, 10, 44, 0, time.UTC)
	judged := time.Date(2026, 4, 17, 8, 55, 45, 0, time.UTC)

	for _, c := range []struct {
		name string
		err  error
		want []string
	}{
		{"a signature", pgperrors.ErrSignatureExpired, []string{"EXPIRY", "self-signatures, had expired"}},
		{"a key", pgperrors.ErrKeyExpired, []string{"EXPIRY", "subkey that signed, had expired"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := expiredBecause(c.err, signed, judged)
			for _, w := range append(c.want, "2026-04-17T08:55:45Z", "2025-03-08T23:10:44Z", "refreshed") {
				if !strings.Contains(got, w) {
					t.Errorf("clause does not say %q:\n%s", w, got)
				}
			}
			if strings.Contains(got, "--sig-covers") {
				t.Errorf("an expiry is advertised as a bytes problem:\n%s", got)
			}
		})
	}
	// The same instant twice says it once and claims no refresh.
	if got := expiredBecause(pgperrors.ErrKeyExpired, signed, signed); strings.Contains(got, "refreshed") {
		t.Errorf("an unrefreshed key is described as refreshed:\n%s", got)
	}
	// An undated signature was judged at the present, and says so.
	if got := expiredBecause(pgperrors.ErrKeyExpired, time.Time{}, time.Time{}); !strings.Contains(got, "carries no creation time") {
		t.Errorf("the undated case does not say so:\n%s", got)
	}
	// Anything else is not this clause's business.
	if got := expiredBecause(errors.New("RSA verification failure"), signed, judged); got != "" {
		t.Errorf("a non-expiry error got an expiry clause: %q", got)
	}
}
