package fetch

import (
	"bytes"
	"fmt"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// Why a signature was refused, in terms of what the SIGNATURE and the KEYRING
// actually say rather than in terms of the one sentence the verifier had.
//
// ⛔⛔ go-zpkg/zpkb#482 IS THIS DEFECT AND ITS OWN DIAGNOSIS WAS AN INSTANCE OF
// IT. The issue reports `gnu.org/help2man` refused as "signature made by
// unknown entity" while the entity is in the keyring and `gpg` verifies the
// same signature — all true. It then names the cause from a packet dump:
// "algo 17 is DSA; digest algo 2 is SHA-1. ProtonMail/go-crypto declines that
// combination, and the refusal surfaces through the unknown entity path."
//
// ⭐ MEASURED 2026-11-19 against the real keyring and the real 95-byte
// signature, and that is not the cause. SHA-1 plays no part:
//
//	readKeyring(fingerprint)              1 key, 156 primary keys scanned
//	entity                                Brendan O'Dea, primary F0DC8E00B28C5995, algo 17
//	signature issuer                      F0DC8E00B28C5995 — the primary key itself
//	KeysById                              1
//	KeysByIdUsage(KeyFlagSign)            0   <- the refusal, and the whole of it
//	SelfSignature.FlagsValid              false, made 2001-06-19
//	PublicKey.VerifySignature by hand     nil — the signature is GOOD, SHA-1 and all
//	CheckDetachedSignature, flags patched nil — one variable, and it passes
//
// So the key is found, the signature is by it, and it verifies. What stops it
// is openpgp/keys.go:343 — `if key.SelfSignature == nil ||
// !key.SelfSignature.FlagsValid { continue }` — against a self-signature from
// 2001 that carries no key-flags subpacket at all. The candidate list comes
// back empty and openpgp/read.go:493 reports ErrUnknownIssuer, which is the
// sentence the caller sees.
//
// ⚠ AND THE SPEC WAS OPENED BEFORE ANY OF THIS WAS RELAXED, WHICH IS WHY IT IS
// NOT RELAXED. The obvious repair — treat a flagless key as sign-capable,
// which is what gpg does — looked like a conformance fix. RFC 9580 §5.2.3.29
// does not say what an absent subpacket implies, and its nearest statement
// goes the other way: "If a list is shorter than an implementation expects,
// the unstated flags are considered to be zero." So go-crypto's refusal is the
// conservative reading, granting sign capability here would be a policy change
// resting on an inference with no line behind it, and whether this pantry wants
// that is the owner's call and not this function's. This names the cause; it
// changes no verdict.
const (
	// declinedUnknownIssuer: no key in the ring has the id the signature names.
	declinedUnknownIssuer = iota
	// declinedNotSignCapable: the key is there and the signature names it, but
	// nothing in the key says it may sign data.
	declinedNotSignCapable
	// declinedWithASigningKey: the key is there and may sign, so the failure is
	// about the BYTES or the cryptography — the only state in which pointing at
	// a different byte stream is sensible advice.
	declinedWithASigningKey
)

// declined is what could be established about a refusal.
//
// ⚠ selfSig IS THE KEY'S, NOT THE DATA SIGNATURE'S, and the two are twenty-one
// years apart in the measured case: 2001-06-19 against 2022-12-15. The message
// says "its self-signature (made …)", so taking the date off the signature in
// hand would have been a sentence about the wrong packet — which is the defect
// this whole file exists to stop, and it was written that way once before this
// field existed.
type declined struct {
	kind    int
	sig     *packet.Signature // the detached signature, nil when unreadable
	selfSig *packet.Signature // the issuer key's self-signature, nil when none
}

// sigIssuer is what the signature says about who made it. A nil result means
// the packet could not be read, in which case nothing is claimed: the verifier
// has already spoken and it is the one authority (see signatureCreationTime).
func sigIssuer(sig []byte) *packet.Signature {
	body := sig
	if bytes.Contains(sig, []byte("-----BEGIN PGP SIGNATURE-----")) {
		block, err := armor.Decode(bytes.NewReader(sig))
		if err != nil {
			return nil
		}
		raw, err := io.ReadAll(block.Body)
		if err != nil {
			return nil
		}
		body = raw
	}
	for r := packet.NewReader(bytes.NewReader(body)); ; {
		p, err := r.Next()
		if err != nil {
			return nil
		}
		if s, ok := p.(*packet.Signature); ok {
			return s
		}
	}
}

// classifyDeclined says which of the three states a refusal is in.
func classifyDeclined(sig []byte, keys openpgp.EntityList) declined {
	s := sigIssuer(sig)
	if s == nil || s.IssuerKeyId == nil {
		// Nothing readable to reason about. Treat it as the state that adds no
		// claim rather than inventing one.
		return declined{kind: declinedWithASigningKey, sig: s}
	}
	if len(keys.KeysByIdUsage(*s.IssuerKeyId, packet.KeyFlagSign)) > 0 {
		return declined{kind: declinedWithASigningKey, sig: s}
	}
	found := keys.KeysById(*s.IssuerKeyId)
	if len(found) == 0 {
		return declined{kind: declinedUnknownIssuer, sig: s}
	}
	return declined{kind: declinedNotSignCapable, sig: s, selfSig: found[0].SelfSignature}
}

// declinedBecause is the clause appended to a refusal, naming the cause the
// verifier actually met. It is empty when nothing can be added.
func (d declined) because(covers string) string {
	switch d.kind {
	case declinedUnknownIssuer:
		return fmt.Sprintf(" — and the signer is genuinely unknown: no key in the file "+
			"you passed has the id %016X that this signature names, so this is a keyring "+
			"problem and not a bytes one", *d.sig.IssuerKeyId)

	case declinedNotSignCapable:
		// ⭐ THE ONE THAT COST go-zpkg/zpkb#482 ITS DIAGNOSIS. Everything the
		// reader needs is here, including the fact that gpg disagrees, so
		// nobody audits a keyring that is fine.
		return fmt.Sprintf(" — ⛔ BUT THE KEY IS PRESENT AND THIS SIGNATURE NAMES IT: "+
			"key %016X is in the file you passed and the signature is by it. What this "+
			"verifier will not do is treat it as a SIGNING key, because its self-signature "+
			"%s carries no key-flags subpacket, so nothing in the key states that it may "+
			"sign data. gpg infers that from the algorithm and accepts such signatures; "+
			"RFC 9580 §5.2.3.29 does not say what an absent subpacket implies, and its "+
			"nearest statement is that unstated flags are considered to be zero. So this "+
			"is neither a wrong key nor wrong bytes: it is a key older than the flag, and "+
			"whether to pin on it is a policy decision",
			*d.sig.IssuerKeyId, d.selfSigAge())

	default:
		// ⚠ AND THE --sig-covers HINT BELONGS ONLY HERE, which is the defect
		// this arm exists to stop. It was appended to EVERY served-mode
		// failure when go-zpkg/zpkb#507 added it, so running the real
		// help2man case printed "if the project signs its UNCOMPRESSED
		// tarball … --sig-covers decompressed checks the other stream" over a
		// failure whose bytes were never in question — the same shape as #482
		// itself, committed while fixing #492.
		if covers == CoversServed {
			return " — the key is in your keyring and may sign, so what did not match is the " +
				"BYTES or the cryptography. If the project signs its UNCOMPRESSED tarball, as " +
				"kernel.org does, --sig-covers decompressed checks the other stream"
		}
		return ""
	}
}

// selfSigAge dates the KEY's self-signature, which is what makes "a key older
// than the flag" checkable by whoever reads the message.
func (d declined) selfSigAge() string {
	if d.selfSig == nil || d.selfSig.CreationTime.IsZero() {
		return "(whose date could not be read)"
	}
	return "(made " + d.selfSig.CreationTime.UTC().Format("2006-01-02") + ")"
}
