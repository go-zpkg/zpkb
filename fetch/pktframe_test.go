package fetch

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// RFC 9580 §4.2: every OpenPGP packet header states its body's length, so the
// next packet can be found without parsing this one. These tests drive each
// header form the spec defines and each refusal, by hand-built octets.

func TestNextPacketReadsEveryHeaderForm(t *testing.T) {
	body := func(n int) []byte { return bytes.Repeat([]byte{0xAB}, n) }
	for _, c := range []struct {
		name    string
		in      []byte
		tag     byte
		rawLen  int
		section string
	}{
		{"current, 1-octet length", append([]byte{0xC6, 3}, body(3)...), 6, 5, "§4.2.1.1"},
		// 2-octet: ((o1-192)<<8)+o2+192; o1=192,o2=8 gives 200.
		{"current, 2-octet length", append([]byte{0xC2, 192, 8}, body(200)...), 2, 203, "§4.2.1.2"},
		{"current, 5-octet length", append([]byte{0xCD, 255, 0, 0, 1, 0}, body(256)...), 13, 262, "§4.2.1.3"},
		// Legacy: bits 5-2 are the type, bits 1-0 the length-type.
		{"legacy, 1-octet length", append([]byte{0x80 | 6<<2 | 0, 4}, body(4)...), 6, 6, "§4.2.2 type 0"},
		{"legacy, 2-octet length", append([]byte{0x80 | 2<<2 | 1, 1, 0}, body(256)...), 2, 259, "§4.2.2 type 1"},
		{"legacy, 4-octet length", append([]byte{0x80 | 14<<2 | 2, 0, 0, 0, 2}, body(2)...), 14, 7, "§4.2.2 type 2"},
	} {
		t.Run(c.name, func(t *testing.T) {
			trailer := []byte{0x99, 0x98}
			p, rest, err := nextPacket(append(append([]byte(nil), c.in...), trailer...))
			if err != nil {
				t.Fatalf("%s: %v", c.section, err)
			}
			if p.tag != c.tag || len(p.raw) != c.rawLen {
				t.Errorf("%s: tag %d, %d octets; want tag %d, %d octets", c.section, p.tag, len(p.raw), c.tag, c.rawLen)
			}
			if !bytes.Equal(rest, trailer) {
				t.Errorf("%s: the rest is %x, want the trailer %x", c.section, rest, trailer)
			}
		})
	}
}

// TestNextPacketRefusesWhatHasNoNextPacket: each refusal is a header that
// states no usable length, so nothing can be stepped past it.
func TestNextPacketRefusesWhatHasNoNextPacket(t *testing.T) {
	for _, c := range []struct {
		name string
		in   []byte
		want string
	}{
		{"bit 7 clear", []byte{0x46, 1, 0}, "bit 7 is clear"},
		{"a Partial Body Length", []byte{0xC2, 0xE0, 0}, "Partial Body Length"},
		{"a Legacy indeterminate length", []byte{0x80 | 2<<2 | 3, 0}, "indeterminate length"},
		{"current: no length octet", []byte{0xC6}, "length octet"},
		{"current: half a 2-octet length", []byte{0xC6, 200}, "2-octet length"},
		{"current: part of a 5-octet length", []byte{0xC6, 255, 0, 0}, "5-octet length"},
		{"legacy: no 1-octet length", []byte{0x80 | 6<<2 | 0}, "legacy 1-octet length"},
		{"legacy: half a 2-octet length", []byte{0x80 | 6<<2 | 1, 0}, "legacy 2-octet length"},
		{"legacy: part of a 4-octet length", []byte{0x80 | 6<<2 | 2, 0, 0}, "legacy 4-octet length"},
		{"a body longer than what remains", []byte{0xC6, 10, 1, 2}, "declares 12 octets and 4 remain"},
		// ⛔ The overflow case, on any word size: 0xFFFFFFFF plus a 6-octet
		// header is compared in uint64, so it cannot wrap past the check.
		{"a 4 GiB body in a 6-octet buffer", []byte{0xC6, 255, 0xFF, 0xFF, 0xFF, 0xFF}, "declares 4294967301 octets"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := nextPacket(c.in)
			if err == nil {
				t.Fatal("accepted")
			}
			if !errors.Is(err, errPacketFraming) {
				t.Errorf("not a framing error: %v", err)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error does not say %q: %v", c.want, err)
			}
		})
	}
	if _, _, err := nextPacket(nil); err != io.EOF {
		t.Errorf("an empty stream: %v, want io.EOF", err)
	}
}

// TestEntityLengthEndsAtTheNextPrimaryKey, the boundary RFC 9580 §10.1 gives a
// certificate — and at a framing error, past which nothing can be located.
func TestEntityLengthEndsAtTheNextPrimaryKey(t *testing.T) {
	uid := []byte{0xCD, 2, 'h', 'i'} // user id, 4 octets
	sig := []byte{0xC2, 1, 0x00}     // signature, 3 octets
	next := []byte{0xC6, 1, 0x04}    // the NEXT primary key
	in := append(append(append([]byte(nil), uid...), sig...), next...)
	if got := entityLength(in); got != 7 {
		t.Errorf("entityLength = %d, want 7 (up to the next primary key)", got)
	}
	broken := append(append([]byte(nil), uid...), 0x46) // then a non-header octet
	if got := entityLength(broken); got != 4 {
		t.Errorf("entityLength = %d, want 4 (up to the framing error)", got)
	}
	if got := entityLength(append([]byte(nil), uid...)); got != 4 {
		t.Errorf("entityLength = %d, want 4 (to the end of the stream)", got)
	}
}

// ⛔⛔ TestTheScanStepsOverAPacketTheParserRefuses is the GNU keyring's 402nd
// key, in miniature: key A, then a packet go-crypto refuses, then key B. The
// old walk stopped at the refused packet and could not reach B.
func TestTheScanStepsOverAPacketTheParserRefuses(t *testing.T) {
	a, b := testKey(t), secondKey(t)
	// A well-framed signature packet (tag 2) whose body is version 99. The
	// framing is valid; the contents are not.
	refused := []byte{0xC2, 1, 99}

	// The CONTROL first: go-crypto's own reader must refuse it, or this test
	// would be measuring nothing.
	if _, err := packet.NewReader(bytes.NewReader(refused)).Next(); err == nil {
		t.Fatal("go-crypto accepted the refused packet; the fixture does not reproduce the stop")
	}

	ring := append(append(binaryPublicKey(t, a), refused...), binaryPublicKey(t, b)...)
	want := strings.ToUpper(fingerprintHex(b))
	e, scanned, err := keyByFingerprint(ring, want)
	if err != nil {
		t.Fatalf("key B past the refused packet was not reached: %v", err)
	}
	if got := strings.ToUpper(fingerprintHex(e)); got != want {
		t.Errorf("found %s, want %s", got, want)
	}
	if scanned != 2 {
		t.Errorf("scanned = %d, want 2 (A, then B)", scanned)
	}
}

// TestAPrimaryKeyTheParserRefusesIsPassed: a tag-6 packet go-crypto cannot
// parse is not the answer to any selector, so it is counted and passed — not
// a reason to stop.
func TestAPrimaryKeyTheParserRefusesIsPassed(t *testing.T) {
	b := testKey(t)
	badKey := []byte{0xC6, 1, 99} // a primary key of version 99
	ring := append(append([]byte(nil), badKey...), binaryPublicKey(t, b)...)
	want := fingerprintHex(b)
	if _, scanned, err := keyByFingerprint(ring, want); err != nil || scanned != 2 {
		t.Errorf("scanned=%d err=%v, want the second key found after counting the first", scanned, err)
	}
}

// TestAFramingErrorStillSaysBothThings: a header that states no usable length
// is the one stop left, and the message must say the selector may be wrong as
// well as that the file breaks — the lesson the old comment recorded.
func TestAFramingErrorStillSaysBothThings(t *testing.T) {
	ring := append(binaryPublicKey(t, testKey(t)), 0xC2, 0xE0, 0) // a partial length
	_, scanned, err := keyByFingerprint(ring, strings.Repeat("0", 40))
	if err == nil {
		t.Fatal("accepted")
	}
	for _, want := range []string{"among the 1 primary key(s)", "framing", "or the selector is wrong"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not say %q: %v", want, err)
		}
	}
	if scanned != 1 {
		t.Errorf("scanned = %d, want 1", scanned)
	}
}

func fingerprintHex(e *openpgp.Entity) string {
	return fmt.Sprintf("%X", e.PrimaryKey.Fingerprint)
}

// FuzzNextPacket: whatever the octets, nextPacket either refuses or returns a
// packet that is a non-empty prefix of its input and advances past it — the
// property that makes the walk terminate.
func FuzzNextPacket(f *testing.F) {
	for _, seed := range [][]byte{
		{0xC6, 3, 1, 2, 3},
		{0xC2, 192, 8},
		{0xCD, 255, 0, 0, 1, 0},
		{0x98, 1, 0},
		{0x89, 1, 0},
		{0x8A, 0, 0, 0, 1, 0},
		{0x8B, 0},
		{0xC2, 0xE0},
		{0x46},
		{0xC6, 255, 0xFF, 0xFF, 0xFF, 0xFF},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		p, rest, err := nextPacket(in)
		if err != nil {
			return
		}
		if len(p.raw) < 2 {
			t.Fatalf("a packet of %d octets: the walk could fail to advance", len(p.raw))
		}
		if !bytes.HasPrefix(in, p.raw) || len(rest) != len(in)-len(p.raw) {
			t.Fatalf("raw is not a prefix, or rest does not follow it")
		}
	})
}
