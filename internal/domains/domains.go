// Package domains implements the custom-domain ownership proof (PRD §10.2,
// SC-14, ADR-011): hostname validation, fresh expiring TXT claims bound to
// this instance, verification against the zone's authoritative name
// servers (never a caching resolver), and A/AAAA/CNAME routing checks for
// the selected ingress mode.
package domains

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"net"
	"strings"

	"golang.org/x/net/idna"
)

// ChallengeLabel is the DNS label under which the claim TXT record lives.
const ChallengeLabel = "_opendeploy-challenge"

// ErrInvalidHostname rejects hostnames that can never be claimed.
var ErrInvalidHostname = errors.New("invalid hostname")

var idnaProfile = idna.New(idna.MapForLookup(), idna.Transitional(false), idna.BidiRule(), idna.StrictDomainName(true))

// Normalize returns the canonical ASCII (punycode), lower-case form of a
// claimable hostname. Wildcards, IP literals, single-label names, local and
// reserved suffixes are rejected: ownership is proven per exact hostname.
func Normalize(host string) (string, error) {
	h := strings.TrimSuffix(strings.TrimSpace(host), ".")
	if h == "" {
		return "", fmt.Errorf("%w: empty", ErrInvalidHostname)
	}
	if strings.Contains(h, "*") {
		return "", fmt.Errorf("%w: wildcard hostnames cannot be claimed; claim each hostname", ErrInvalidHostname)
	}
	if net.ParseIP(strings.Trim(h, "[]")) != nil {
		return "", fmt.Errorf("%w: IP addresses cannot be claimed", ErrInvalidHostname)
	}
	a, err := idnaProfile.ToASCII(h)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidHostname, err)
	}
	a = strings.ToLower(a)
	if len(a) > 253 {
		return "", fmt.Errorf("%w: longer than 253 characters", ErrInvalidHostname)
	}
	labels := strings.Split(a, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("%w: a fully qualified name is required", ErrInvalidHostname)
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {
			return "", fmt.Errorf("%w: bad label %q", ErrInvalidHostname, l)
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", fmt.Errorf("%w: bad character in %q", ErrInvalidHostname, l)
			}
		}
	}
	tld := labels[len(labels)-1]
	if tld[0] >= '0' && tld[0] <= '9' {
		return "", fmt.Errorf("%w: numeric top-level label", ErrInvalidHostname)
	}
	for _, s := range []string{"localhost", "local", "internal", "invalid", "test", "example", "arpa", "home.arpa", "lan"} {
		if a == s || strings.HasSuffix(a, "."+s) {
			return "", fmt.Errorf("%w: reserved or local suffix .%s", ErrInvalidHostname, s)
		}
	}
	if labels[0] == ChallengeLabel {
		return "", fmt.Errorf("%w: reserved label", ErrInvalidHostname)
	}
	return a, nil
}

// Within reports whether host equals or is below suffix.
func Within(host, suffix string) bool {
	suffix = strings.ToLower(strings.TrimSuffix(suffix, "."))
	return suffix != "" && (host == suffix || strings.HasSuffix(host, "."+suffix))
}

// ChallengeName is the TXT owner name for a hostname.
func ChallengeName(host string) string { return ChallengeLabel + "." + host }

// NewToken returns a fresh 160-bit claim token.
func NewToken() string {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
}

// TXTValue is the exact record content a claim requires. It binds the proof
// to this OpenDeploy instance and to the claim's random token; tokens of
// earlier (expired, detached or other-instance) claims never match.
func TXTValue(instanceID, token string) string {
	return InstancePrefix(instanceID) + "token=" + token
}

// InstancePrefix is the part of a claim record that names the instance; a
// relay authorises custom-domain routes for an instance only while such a
// record is published (the domain owner keeps it for relay mode).
func InstancePrefix(instanceID string) string {
	return "opendeploy-claim=v1;instance=" + instanceID + ";"
}
