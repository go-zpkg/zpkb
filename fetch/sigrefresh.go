package fetch

import (
	"errors"
	"fmt"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	pgperrors "github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// refusalCause is the two parts of a refusal that name its cause: the lead
// sentence and the clause after it.
//
// ⛔ AN EXPIRY IS ITS OWN CAUSE. It used to fall into classifyDeclined's "key
// present and may sign" arm and get the --sig-covers BYTES hint — measured on
// gnu.org/libidn2 2.3.8 (go-zpkg/zpkb#512), the same mislabelling
// go-zpkg/zpkb#482 was about. A function rather than lines in digestVerified
// because an expiry cannot be produced THROUGH DigestVerified honestly:
// go-crypto will not sign outside a key's validity, nor before its creation,
// so every branch here is driven directly instead.
func refusalCause(err error, d declined, covers string, signedAt, judgedAt time.Time) (lead, why string) {
	if e := expiredBecause(err, signedAt, judgedAt); e != "" {
		return "do not pin this until you know why", e
	}
	lead = "what failed is WHO signed them, so do not pin this until you know why"
	if d.kind != declinedWithASigningKey {
		lead = "do not pin this until you know why"
	}
	return lead, d.because(covers)
}

// expiredBecause is the cause clause for a refusal on EXPIRY, or "" when the
// error is something else. It names both instants, because after #512 the one
// the checks ran at need not be the one the signature carries.
func expiredBecause(err error, signedAt, judgedAt time.Time) string {
	what := ""
	switch {
	case errors.Is(err, pgperrors.ErrKeyExpired):
		what = "the signing key, or the subkey that signed, had expired"
	case errors.Is(err, pgperrors.ErrSignatureExpired):
		what = "the signature, or one of the key's own self-signatures, had expired"
	default:
		return ""
	}
	at := judgedAt.UTC().Format(time.RFC3339)
	if signedAt.IsZero() {
		at = "the present (the signature carries no creation time)"
	} else if judgedAt.After(signedAt) {
		at += fmt.Sprintf(", the key's newest self-signature — later than the signature's own %s, because the key was refreshed after it signed", signedAt.UTC().Format(time.RFC3339))
	}
	return fmt.Sprintf(" — ⛔ THE CAUSE IS EXPIRY, NOT THE KEY OR THE BYTES: %s, judged at %s. "+
		"Neither a missing key nor wrong bytes; whether a release signed while the key was valid "+
		"can still be pinned is the expiry rule's question (go-zpkg/zpkb#484, #512)", what, at)
}

// The instant every check is judged at, when the signing key has been
// REFRESHED since it signed (go-zpkg/zpkb#512).
//
// ⛔⛔ A DEFECT IN go-zpkg/zpkb#484'S OWN FIX, FOUND BY ITS AUTHOR. #484 moved
// the clock from time.Now() to the data signature's creation instant, so a key
// that lapsed after signing still vouches for what it signed. Right for expiry.
// But go-crypto judges, at that ONE instant, the data signature AND the key's
// self-signatures (openpgp/read.go:585-618), and packet/signature.go:762-765
// counts a signature CREATED AFTER the instant as expired:
//
//	if sig.CreationTime.Unix() > currentTime.Unix() { return true }
//
// A keyring holds a key's CURRENT self-signatures. A maintainer who refreshes
// them — routinely, to extend an expiry — makes them newer than every release
// signed before. Judged at an older release's instant, the refreshed
// self-signature "does not exist yet", and the release is refused. Measured on
// gnu.org/libidn2 2.3.8: data signature 2025-03-08, Simon Josefsson's user-ID
// self-signature in the GNU keyring 2026-04-17, refused as "signature expired".
//
// ⭐ So the clock is the LATER of the data signature and the issuer key's
// newest relevant self-signature, that self-signature's instant capped at
// time.Now() — and never earlier than the data signature's own:
//
//   - with no refresh it is #484's clock exactly;
//   - with a refresh, the key is judged as its current self-signatures describe
//     it, at the instant they were made — after the data signature, so the data
//     signature exists by then;
//   - the cap means a self-signature dated in the future cannot carry the clock
//     with it;
//   - revocation is judged at that instant too, which is LATER, i.e. stricter.
//
// ⚠ ONE BEHAVIOUR CHANGE, stated rather than hidden: a data signature carrying
// its OWN lifetime that ended between its creation and the refresh is now
// refused, where #484 accepted it. One clock cannot serve both, and a data
// signature with an expiry is rare in release signing; the refusal names the
// cause and the instant (see expiredBecause).
func refreshedClock(signedAt time.Time, sig []byte, keys openpgp.EntityList, now time.Time) time.Time {
	s := sigIssuer(sig)
	if s == nil || s.IssuerKeyId == nil {
		return signedAt
	}
	// ⛔⛔ THE CAP LIMITS THE REFRESH, NEVER THE SIGNATURE'S OWN INSTANT. The
	// first version capped the whole clock at the present, and #484's own
	// TestAnHourOfClockSkewIsNotTreatedAsTheFuture caught it: a signature dated
	// twenty minutes ahead — allowed, sigTimeConfig accepts an hour of skew — was
	// judged at the present, BEFORE its own creation, so go-crypto counted the
	// data signature itself as "created after now". The signature's future
	// dating is sigTimeConfig's to police; this only decides whether a refresh
	// moves the clock later, and a refresh from the future may not.
	clock := signedAt
	later := func(p *packet.Signature) {
		if p == nil {
			return
		}
		t := p.CreationTime
		if t.After(now) {
			t = now
		}
		if t.After(clock) {
			clock = t
		}
	}
	for _, k := range keys.KeysById(*s.IssuerKeyId) {
		primary, _ := k.Entity.PrimarySelfSignature()
		later(primary)
		// For a subkey: its binding signature and the cross-signature embedded
		// in it — the two read.go:591 adds to what it checks. For the primary
		// key, SelfSignature is the primary self-signature again.
		later(k.SelfSignature)
		if k.SelfSignature != nil {
			later(k.SelfSignature.EmbeddedSignature)
		}
	}
	return clock
}
