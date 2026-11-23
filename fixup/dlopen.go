package fixup

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
)

// The .note.dlopen format, read from
// https://uapi-group.org/specifications/specs/elf_dlopen_metadata/ (the page
// systemd.io/ELF_DLOPEN_METADATA now redirects to):
//
//	section  .note.dlopen, 4-byte aligned, 0-padded
//	owner    "FDO", type 0x407c0c0a
//	value    an array of JSON objects, a zero-terminated UTF-8 string
//	fields   soname (array, mandatory, >= 1 element; alternatives, MOST
//	         PREFERRED FIRST, of which a parser selects the first available),
//	         feature, description, priority (required | recommended | suggested,
//	         "recommended" when omitted)
//	notes    several notes mean one long array
const (
	dlopenSection  = ".note.dlopen"
	dlopenNoteType = 0x407c0c0a
	dlopenOwner    = "FDO"

	// The bounds are on untrusted input: a section is read whole, so its size
	// is refused before it is read, and every count below is a ceiling.
	maxDlopenBytes   = 1 << 20
	maxDlopenEntries = 4096
	maxDlopenSonames = 64
)

// Dlopen priorities.
const (
	PriorityRequired    = "required"
	PriorityRecommended = "recommended"
	PrioritySuggested   = "suggested"
)

// DlopenEntry is one dependency a binary loads with dlopen(3).
type DlopenEntry struct {
	Feature     string
	Description string
	Priority    string   // always one of the three constants
	Sonames     []string // alternatives, most preferred first
}

type dlopenJSON struct {
	Feature     string   `json:"feature"`
	Description string   `json:"description"`
	Priority    string   `json:"priority"`
	Soname      []string `json:"soname"`
}

// ParseDlopenNotes reads the contents of a .note.dlopen section. It never
// panics and never allocates more than its bounds allow, whatever the bytes.
func ParseDlopenNotes(data []byte, bo binary.ByteOrder) ([]DlopenEntry, error) {
	if len(data) > maxDlopenBytes {
		return nil, fmt.Errorf("%s: %d bytes exceeds the %d limit", dlopenSection, len(data), maxDlopenBytes)
	}
	var out []DlopenEntry
	for len(data) > 0 {
		if len(data) < 12 {
			return nil, fmt.Errorf("%s: truncated note header (%d bytes)", dlopenSection, len(data))
		}
		namesz := uint64(bo.Uint32(data[0:4]))
		descsz := uint64(bo.Uint32(data[4:8]))
		typ := bo.Uint32(data[8:12])
		nameEnd := 12 + align4(namesz)
		descEnd := nameEnd + align4(descsz)
		if descEnd > uint64(len(data)) {
			return nil, fmt.Errorf("%s: note of %d+%d bytes overruns the section", dlopenSection, namesz, descsz)
		}
		name := data[12 : 12+namesz]
		desc := data[nameEnd : nameEnd+descsz]
		data = data[descEnd:]
		if typ != dlopenNoteType || string(bytes.TrimRight(name, "\x00")) != dlopenOwner {
			continue // another owner's note: not ours to judge
		}
		desc = bytes.TrimRight(desc, "\x00")
		var objs []dlopenJSON
		if err := json.Unmarshal(desc, &objs); err != nil {
			return nil, fmt.Errorf("%s: bad JSON: %w", dlopenSection, err)
		}
		for _, o := range objs {
			if len(out) >= maxDlopenEntries {
				return nil, fmt.Errorf("%s: more than %d entries", dlopenSection, maxDlopenEntries)
			}
			if len(o.Soname) == 0 {
				return nil, fmt.Errorf("%s: an entry (feature %q) has no soname", dlopenSection, o.Feature)
			}
			if len(o.Soname) > maxDlopenSonames {
				return nil, fmt.Errorf("%s: an entry lists %d sonames, more than %d", dlopenSection, len(o.Soname), maxDlopenSonames)
			}
			pr := strings.ToLower(o.Priority)
			switch pr {
			case PriorityRequired, PriorityRecommended, PrioritySuggested:
			default:
				// Omitted: the spec says assume recommended. An unknown word is
				// the same, and stricter than a miss would be for "required".
				pr = PriorityRecommended
			}
			out = append(out, DlopenEntry{Feature: o.Feature, Description: o.Description, Priority: pr, Sonames: o.Soname})
		}
	}
	return out, nil
}

func align4(n uint64) uint64 { return (n + 3) &^ 3 }
