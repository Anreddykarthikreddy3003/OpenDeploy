// Package ids generates opaque, prefixed, unguessable identifiers.
//
// Identifiers are never derived from user input so they cannot be used to
// guess other tenants' resources (IDOR resistance, PRD Q9/Q19).
package ids

import (
	"crypto/rand"
	"encoding/base32"
	"strings"
)

var enc = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// New returns prefix_<26 chars> backed by 128 bits of randomness.
func New(prefix string) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("ids: crypto/rand failure: " + err.Error())
	}
	return prefix + "_" + enc.EncodeToString(b[:])
}

// Token returns a URL-safe random token with n bytes of entropy.
func Token(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("ids: crypto/rand failure: " + err.Error())
	}
	return enc.EncodeToString(b)
}

// HasPrefix reports whether id is a well-formed identifier with prefix.
func HasPrefix(id, prefix string) bool {
	if !strings.HasPrefix(id, prefix+"_") {
		return false
	}
	rest := id[len(prefix)+1:]
	if len(rest) != 26 {
		return false
	}
	for _, c := range rest {
		if !(c >= 'a' && c <= 'z') && !(c >= '2' && c <= '7') {
			return false
		}
	}
	return true
}
