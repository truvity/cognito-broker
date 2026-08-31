// Package tenant generates the tenant identifiers an integration suite
// runs against.
//
// These are deliberately random per invocation rather than fixed. The
// platform accepts any non-empty tenant on the header and stores nothing
// in advance, so a fresh pair per run gives each run its own empty world
// — no leftover documents from a previous run to make a test pass or
// fail for reasons it did not create.
//
// The names are the caller's, not this package's: a suite that wants
// `primary` and `secondary` gets those keys, and one that wants
// `alice` and `bob` gets those. Keeping the names out of the tool is
// what lets several repositories share it without any of them being
// privileged.
package tenant

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

// Generate returns one identifier per name, in the order given.
//
// Duplicate names are refused rather than silently collapsed: asking for
// `primary,primary` almost certainly means a typo, and returning a
// single-entry map would present as a test that mysteriously shares a
// tenant with itself.
func Generate(names []string) (map[string]string, error) {
	if len(names) == 0 {
		return nil, nil
	}

	out := make(map[string]string, len(names))

	for _, raw := range names {
		name := strings.TrimSpace(raw)
		if name == "" {
			return nil, fmt.Errorf("tenant: empty name in the list")
		}

		if _, seen := out[name]; seen {
			return nil, fmt.Errorf("tenant: %q listed twice", name)
		}

		id, err := uuidV4()
		if err != nil {
			return nil, err
		}

		out[name] = id
	}

	return out, nil
}

// ParseNames splits a comma-separated list, ignoring empty entries so a
// trailing comma is not an error.
func ParseNames(raw string) []string {
	out := []string{}

	for _, part := range strings.Split(raw, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}

	return out
}

// uuidV4 builds a random UUID from crypto/rand.
//
// Hand-rolled rather than pulling a dependency for sixteen bytes: the
// layout is fixed by RFC 4122 and the only thing that can go wrong — a
// short read from the entropy source — is checked below rather than
// ignored.
func uuidV4() (string, error) {
	var b [16]byte

	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("tenant: read entropy: %w", err)
	}

	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10

	h := hex.EncodeToString(b[:])

	return strings.Join([]string{h[0:8], h[8:12], h[12:16], h[16:20], h[20:32]}, "-"), nil
}
