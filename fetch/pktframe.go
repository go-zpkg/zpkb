package fetch

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Locating OpenPGP packets by their HEADERS alone, so a packet the parser
// would refuse can be stepped over instead of ending the scan.
//
// ⛔⛔ WHY THIS EXISTS: 212 OF 614 GNU MAINTAINERS' KEYS WERE UNREACHABLE.
// keyByFingerprint used ProtonMail/go-crypto's packet.Reader to walk a keyring,
// and that reader cannot be resynchronised after a packet it refuses — so the
// walk stopped there. Against https://ftp.gnu.org/gnu/gnu-keyring.gpg it
// stopped at the 402nd primary key, on "Cannot have multiple embedded
// signatures". Measured 2026-11-20: `gpg --show-keys` reads 614 primary keys
// from the same file. Every GNU release signed by a key past that point could
// not be verified, and gnu.org/libidn2 2.3.8 is one — its signer, Simon
// Josefsson's B1D2BD1375BECB784CF4F8C4D73CF638C53C06BE, sits beyond it.
//
// ⭐ The way through is in the format itself. Every packet header states the
// length of its body (RFC 9580 §4.2), so the next packet's position is known
// without understanding this one. gpg reads all 614 that way. Here only the
// header is decoded; go-crypto still parses every packet that is USED.
//
// ⛔ What is refused rather than guessed, both from the spec:
//
//   - a Partial Body Length (§4.2.1.4: "MUST NOT be used for any other packet
//     types" than literal, compressed or encrypted data — none of which belongs
//     in a keyring);
//   - a Legacy indeterminate length (§4.2.2: "the packet extends until the end
//     of the file") — there is no next packet to find after one.
//
// Either ends the scan, loudly, as a malformed header does.

// tagPublicKey is the Packet Type ID of a primary public key (RFC 9580 §5.5.1.1).
// Subkeys are 14 and are not candidates: --fingerprint names a primary.
const tagPublicKey = 6

// framedPacket is one packet, located by its header: its Packet Type ID and
// its whole encoding, header included, so it can be handed to a parser as is.
type framedPacket struct {
	tag byte
	raw []byte
}

// errPacketFraming is the class of every refusal below, so a caller can tell
// "the bytes are not a packet stream here" from other failures.
var errPacketFraming = errors.New("OpenPGP packet framing")

// nextPacket locates the packet at the start of b and returns it with the
// bytes after it. io.EOF means b is empty.
//
// ⛔ EVERY LENGTH IS COMPARED IN uint64. A 5-octet length reaches 0xFFFFFFFF
// (§4.2.1.3); on a 32-bit build `int` is 32 bits, so adding a header length to
// a body length in int could wrap and pass the bounds check it was meant to
// fail. The conversion back to int happens only after the total is known to be
// at most len(b), which fits.
func nextPacket(b []byte) (framedPacket, []byte, error) {
	if len(b) == 0 {
		return framedPacket{}, nil, io.EOF
	}
	h := b[0]
	if h&0x80 == 0 {
		return framedPacket{}, nil, fmt.Errorf("%w: octet 0x%02x is not a packet header — bit 7 is clear (RFC 9580 §4.2)", errPacketFraming, h)
	}
	var (
		tag  byte
		hdr  uint64
		body uint64
	)
	if h&0x40 != 0 {
		// OpenPGP format: bits 5-0 are the type, the length follows (§4.2.1).
		tag = h & 0x3f
		if len(b) < 2 {
			return framedPacket{}, nil, truncated("length octet", len(b))
		}
		switch o1 := b[1]; {
		case o1 < 192: // §4.2.1.1
			hdr, body = 2, uint64(o1)
		case o1 < 224: // §4.2.1.2
			if len(b) < 3 {
				return framedPacket{}, nil, truncated("2-octet length", len(b))
			}
			hdr, body = 3, (uint64(o1)-192)<<8+uint64(b[2])+192
		case o1 == 255: // §4.2.1.3
			if len(b) < 6 {
				return framedPacket{}, nil, truncated("5-octet length", len(b))
			}
			hdr, body = 6, uint64(binary.BigEndian.Uint32(b[2:6]))
		default: // 224..254, §4.2.1.4
			return framedPacket{}, nil, fmt.Errorf("%w: packet type %d uses a Partial Body Length, which RFC 9580 §4.2.1.4 allows only for data packets — not in a keyring", errPacketFraming, tag)
		}
	} else {
		// Legacy format: bits 5-2 are the type, bits 1-0 the length-type (§4.2.2).
		tag = (h >> 2) & 0x0f
		switch h & 0x03 {
		case 0:
			if len(b) < 2 {
				return framedPacket{}, nil, truncated("legacy 1-octet length", len(b))
			}
			hdr, body = 2, uint64(b[1])
		case 1:
			if len(b) < 3 {
				return framedPacket{}, nil, truncated("legacy 2-octet length", len(b))
			}
			hdr, body = 3, uint64(binary.BigEndian.Uint16(b[1:3]))
		case 2:
			if len(b) < 5 {
				return framedPacket{}, nil, truncated("legacy 4-octet length", len(b))
			}
			hdr, body = 5, uint64(binary.BigEndian.Uint32(b[1:5]))
		default:
			return framedPacket{}, nil, fmt.Errorf("%w: packet type %d has a Legacy indeterminate length, which RFC 9580 §4.2.2 says extends to the end of the file — there is no next packet to find", errPacketFraming, tag)
		}
	}
	total := hdr + body
	if total > uint64(len(b)) {
		return framedPacket{}, nil, fmt.Errorf("%w: packet type %d declares %d octets and %d remain", errPacketFraming, tag, total, len(b))
	}
	n := int(total)
	return framedPacket{tag: tag, raw: b[:n]}, b[n:], nil
}

func truncated(what string, have int) error {
	return fmt.Errorf("%w: the stream ends inside a header (%s, %d octet(s) left)", errPacketFraming, what, have)
}

// entityLength is how many octets of b belong to the entity that ends where
// the next primary key begins — the boundary RFC 9580 §10.1 gives a
// Transferable Public Key. A framing error ends the entity there: what follows
// cannot be located, so it cannot belong to it either.
func entityLength(b []byte) int {
	n := 0
	for rest := b; ; {
		p, next, err := nextPacket(rest)
		if err != nil || p.tag == tagPublicKey {
			return n
		}
		n += len(p.raw)
		rest = next
	}
}
