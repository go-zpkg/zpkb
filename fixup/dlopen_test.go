package fixup

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestParseDlopenNotes(t *testing.T) {
	le := binary.LittleEndian
	two := append(dlopenNote(`[{"feature":"a","priority":"required","soname":["liba.so.1"]}]`),
		dlopenNote(`[{"feature":"b","soname":["libb.so.1","libb.so.2"],"description":"d"}]`)...)
	got, err := ParseDlopenNotes(two, le)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Priority != PriorityRequired || got[1].Priority != PriorityRecommended ||
		got[1].Sonames[1] != "libb.so.2" || got[1].Description != "d" {
		t.Fatalf("%+v", got)
	}
}

func TestParseDlopenNotesSkipsOtherOwners(t *testing.T) {
	// A GNU build-id style note in the same section is not ours to judge.
	other := []byte{4, 0, 0, 0, 4, 0, 0, 0, 3, 0, 0, 0, 'G', 'N', 'U', 0, 1, 2, 3, 4}
	got, err := ParseDlopenNotes(append(other, dlopenNote(`[{"soname":["x.so"]}]`)...), binary.LittleEndian)
	if err != nil || len(got) != 1 {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestParseDlopenNotesBigEndian(t *testing.T) {
	var b []byte
	for _, v := range []uint32{4, 20, dlopenNoteType} {
		b = binary.BigEndian.AppendUint32(b, v)
	}
	b = append(b, "FDO\x00"...)
	b = append(b, `[{"soname":["x"]}]`...)
	b = append(b, 0, 0) // desc 19 bytes -> padded to 20
	got, err := ParseDlopenNotes(b, binary.BigEndian)
	if err != nil || len(got) != 1 {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestParseDlopenNotesRefuses(t *testing.T) {
	le := binary.LittleEndian
	huge := make([]byte, 12) // namesz = 0xffffffff
	le.PutUint32(huge[0:], 0xffffffff)
	many := `[` + strings.Repeat(`{"soname":["a"]},`, maxDlopenEntries) + `{"soname":["a"]}]`
	for name, data := range map[string][]byte{
		"truncated header": {1, 2, 3},
		"overrun":          huge,
		"bad json":         dlopenNote(`[{`),
		"not an array":     dlopenNote(`{"soname":["a"]}`),
		"no soname":        dlopenNote(`[{"feature":"x"}]`),
		"too many entries": dlopenNote(many),
		"too many sonames": dlopenNote(`[{"soname":[` + strings.Repeat(`"a",`, maxDlopenSonames) + `"a"]}]`),
		"over the limit":   make([]byte, maxDlopenBytes+1),
	} {
		if _, err := ParseDlopenNotes(data, le); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func FuzzParseDlopenNotes(f *testing.F) {
	f.Add(dlopenNote(`[{"feature":"a","priority":"required","soname":["liba.so.1"]}]`))
	f.Add(dlopenNote(`[{"soname":["a","b"]}]`))
	f.Add([]byte{})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, bo := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
			entries, err := ParseDlopenNotes(data, bo)
			if err != nil {
				continue
			}
			if len(entries) > maxDlopenEntries {
				t.Fatalf("%d entries", len(entries))
			}
			for _, e := range entries {
				if len(e.Sonames) == 0 || len(e.Sonames) > maxDlopenSonames {
					t.Fatalf("soname count %d", len(e.Sonames))
				}
				switch e.Priority {
				case PriorityRequired, PriorityRecommended, PrioritySuggested:
				default:
					t.Fatalf("priority %q", e.Priority)
				}
			}
		}
	})
}
