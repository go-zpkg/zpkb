package main

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/go-zpkg/artifact"
)

// ⛔ TRUST FOR THE SOURCE, AND ONLY THE SOURCE.
//
// A promotion reads a seed artifact that was signed with the seed key, which is
// correctly NOT in the default trust set: clients must never trust it. Without a
// way to say "believe this key when reading the SOURCE", the production promotion
// could never verify what it promotes (promo-r2: "signed by no trusted key; 1
// further signature was made by a key that is not in the trust set").
//
// Widening the DESTINATION's trust (ZPKG_EXTRA_TRUSTED_KEYS) is the wrong tool: it
// is what clients and the post-publish test trust, and a promotion must not widen
// that. --source-trust is applied for the duration of one read of the source
// (sourceVerified) and nothing else: it is not exported to a child process, not
// left in this process's environment, and not written into the stage plan.

// maxSourceTrustedKeys bounds the list: a promotion has one source registry, and
// a long list is a trust set in disguise.
const maxSourceTrustedKeys = 8

// parseSourceTrust validates a whitespace-separated list of name:RW<base64>
// entries the way ZPKG_EXTRA_TRUSTED_KEYS is, and returns them one per element.
func parseSourceTrust(v string) ([]string, error) {
	fields := strings.Fields(v)
	if len(fields) > maxSourceTrustedKeys {
		return nil, fmt.Errorf("--source-trust: %d keys, more than the %d allowed", len(fields), maxSourceTrustedKeys)
	}
	for i, f := range fields {
		if _, err := artifact.ParseSigner(f); err != nil {
			// The entry may be a secret pasted by mistake: neither it nor the
			// parser's error (which quotes it) is echoed.
			return nil, fmt.Errorf("--source-trust: entry %d is not name:RW<base64>", i+1)
		}
	}
	return fields, nil
}

// sourceTrust is the keys believed when reading the source. Set by factory for
// the length of a run, empty otherwise.
var sourceTrust []string

var sourceTrustMu sync.Mutex

// underSourceTrust runs fn with keys added to the trust set artifact loads, and
// puts the environment back exactly as it was, set or unset, before returning.
// artifact reads its trust set from the environment at the call, so this is the
// narrowest scope that needs no change to it; the mutex keeps two reads from
// restoring over each other.
func underSourceTrust(keys []string, fn func() error) error {
	if len(keys) == 0 {
		return fn()
	}
	sourceTrustMu.Lock()
	defer sourceTrustMu.Unlock()
	old, had := os.LookupEnv(artifact.ExtraTrustedKeysEnv)
	combined := strings.TrimSpace(artifact.Env(artifact.ExtraTrustedKeysEnv) + " " + strings.Join(keys, " "))
	// Setenv fails only for an empty or NUL-bearing name or a NUL in the value;
	// the keys were validated and the name is a constant.
	os.Setenv(artifact.ExtraTrustedKeysEnv, combined)
	defer func() {
		if had {
			os.Setenv(artifact.ExtraTrustedKeysEnv, old)
		} else {
			os.Unsetenv(artifact.ExtraTrustedKeysEnv)
		}
	}()
	return fn()
}
