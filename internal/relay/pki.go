// Package relay implements the hardened OpenDeploy relay (PRD §10.3,
// SC-13): a public relay-server that routes raw TLS/HTTP connections by
// SNI/Host to authenticated instance tunnels, and the relay-agent that
// holds the tunnel and splices streams to the local Caddy edge. TLS for
// application traffic terminates at the local edge; the relay never holds
// application keys and only observes routing metadata.
package relay

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Credential lifetimes.
const (
	AgentCertTTL  = 24 * time.Hour
	serverCertTTL = 30 * 24 * time.Hour
	caTTL         = 10 * 365 * 24 * time.Hour
	identityHost  = "opendeploy-relay"
)

// Identity is the authenticated principal of a tunnel.
type Identity struct {
	Tenant   string `json:"tenant"`
	Instance string `json:"instance"`
}

func (i Identity) String() string { return i.Tenant + "/" + i.Instance }

var idRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,38}[a-z0-9]$`)

// ValidID reports whether s is a valid tenant or instance ID (a DNS label,
// since instances own <instance>.<public-suffix>).
func ValidID(s string) bool { return idRe.MatchString(s) }

// URI encodes the identity as the certificate's URI SAN.
func (i Identity) URI() *url.URL {
	return &url.URL{Scheme: "spiffe", Host: identityHost, Path: "/t/" + i.Tenant + "/i/" + i.Instance}
}

// IdentityFromCert extracts the identity from a verified client cert.
func IdentityFromCert(c *x509.Certificate) (Identity, error) {
	if len(c.URIs) != 1 {
		return Identity{}, errors.New("certificate must carry exactly one identity URI")
	}
	u := c.URIs[0]
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if u.Scheme != "spiffe" || u.Host != identityHost || len(parts) != 4 || parts[0] != "t" || parts[2] != "i" || !ValidID(parts[1]) || !ValidID(parts[3]) {
		return Identity{}, fmt.Errorf("malformed identity %q", u.String())
	}
	return Identity{Tenant: parts[1], Instance: parts[3]}, nil
}

// CA is the relay's credential authority.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
	PEM  []byte
}

// Fingerprint is the SHA-256 of the CA certificate (pinned by agents).
func (c *CA) Fingerprint() string {
	s := sha256.Sum256(c.Cert.Raw)
	return hex.EncodeToString(s[:])
}

// Pool returns a pool containing only this CA.
func (c *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.Cert)
	return p
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		panic(err)
	}
	return n
}

// LoadOrCreateCA loads ca.crt/ca.key from dir, creating them on first use.
func LoadOrCreateCA(dir string) (*CA, error) {
	cp, kp := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	if cb, err := os.ReadFile(cp); err == nil {
		kb, err := os.ReadFile(kp)
		if err != nil {
			return nil, err
		}
		return parseCA(cb, kb)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "OpenDeploy Relay CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(caTTL), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	cb := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kb := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})
	if err := writeFileAtomic(kp, kb, 0o600); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(cp, cb, 0o644); err != nil {
		return nil, err
	}
	return parseCA(cb, kb)
}

func parseCA(cb, kb []byte) (*CA, error) {
	c, err := ParseCertPEM(cb)
	if err != nil {
		return nil, err
	}
	b, _ := pem.Decode(kb)
	if b == nil {
		return nil, errors.New("ca.key: no PEM block")
	}
	k, err := x509.ParseECPrivateKey(b.Bytes)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: c, Key: k, PEM: cb}, nil
}

// ParseCertPEM parses the first certificate in a PEM blob.
func ParseCertPEM(b []byte) (*x509.Certificate, error) {
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, errors.New("no PEM certificate")
	}
	return x509.ParseCertificate(blk.Bytes)
}

// IssueServer issues the tunnel endpoint's TLS certificate.
func (c *CA) IssueServer(names []string, key *ecdsa.PrivateKey) ([]byte, error) {
	tpl := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-5 * time.Minute), NotAfter: time.Now().Add(serverCertTTL),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, c.Cert, &key.PublicKey, c.Key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// IssueAgent signs a short-lived client certificate for id over the CSR's
// public key. The CSR's own subject and SANs are ignored: identity comes
// only from the enrollment record or the already-authenticated peer.
func (c *CA) IssueAgent(id Identity, csrPEM []byte, ttl time.Duration) ([]byte, *x509.Certificate, error) {
	blk, _ := pem.Decode(csrPEM)
	if blk == nil || blk.Type != "CERTIFICATE REQUEST" {
		return nil, nil, errors.New("no PEM certificate request")
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		return nil, nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, fmt.Errorf("csr signature: %w", err)
	}
	if pk, ok := csr.PublicKey.(*ecdsa.PublicKey); !ok || pk.Curve != elliptic.P256() {
		return nil, nil, errors.New("agent key must be ECDSA P-256")
	}
	if ttl <= 0 || ttl > AgentCertTTL {
		ttl = AgentCertTTL
	}
	tpl := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: id.String()}, URIs: []*url.URL{id.URI()},
		NotBefore: time.Now().Add(-5 * time.Minute), NotAfter: time.Now().Add(ttl),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, c.Cert, csr.PublicKey, c.Key)
	if err != nil {
		return nil, nil, err
	}
	cert, _ := x509.ParseCertificate(der)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), cert, nil
}

// NewCSR creates an agent key and CSR (the private key never leaves the
// instance).
func NewCSR() (*ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "opendeploy-relay-agent"}}, key)
	if err != nil {
		return nil, nil, err
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// EncodeKey PEM-encodes an EC private key.
func EncodeKey(k *ecdsa.PrivateKey) []byte {
	der, _ := x509.MarshalECPrivateKey(k)
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// EnrollToken is the one-time secret an operator hands to an instance:
// odr1.<id>.<secret>.<ca-fingerprint>. The fingerprint lets the agent pin
// the relay CA before it trusts anything the relay says.
type EnrollToken struct {
	ID, Secret, CAFingerprint string
}

func (t EnrollToken) String() string {
	return "odr1." + t.ID + "." + t.Secret + "." + t.CAFingerprint
}

// ParseEnrollToken parses a token string.
func ParseEnrollToken(s string) (EnrollToken, error) {
	p := strings.Split(strings.TrimSpace(s), ".")
	if len(p) != 4 || p[0] != "odr1" || len(p[1]) != 16 || len(p[2]) != 64 || len(p[3]) != 64 {
		return EnrollToken{}, errors.New("malformed enrollment token")
	}
	return EnrollToken{ID: p[1], Secret: p[2], CAFingerprint: p[3]}, nil
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func hashSecret(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func equalHash(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

func writeFileAtomic(path string, b []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
