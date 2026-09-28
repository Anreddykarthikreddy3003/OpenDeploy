package backup

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Format identifies the backup layout.
const Format = "odbk1"

// Component is one logical piece of a backup (a DB snapshot, the sealed
// secret bundle, a volume, the artifact store).
type Component struct {
	Name   string `json:"name"`   // path inside the archive
	Kind   string `json:"kind"`   // platform-db | audit-db | secrets | artifacts | volume | config
	Size   int64  `json:"size"`   // plaintext bytes
	SHA256 string `json:"sha256"` // of the plaintext component
	Ref    string `json:"ref,omitempty"`
}

// Manifest describes a backup. Everything needed to decrypt is here except
// the master key; the manifest itself is signed.
type Manifest struct {
	Format           string      `json:"format"`
	ID               string      `json:"id"`
	CreatedAt        time.Time   `json:"created_at"`
	Node             string      `json:"node"`
	Version          string      `json:"version"`
	SchemaVersion    int         `json:"schema_version"`
	Components       []Component `json:"components"`
	PlainSize        int64       `json:"plain_size"`
	CipherSize       int64       `json:"cipher_size"`
	CipherSHA256     string      `json:"cipher_sha256"`
	ChunkSize        int         `json:"chunk_size"`
	NoncePrefix      string      `json:"nonce_prefix"` // base64
	WrappedDEK       string      `json:"wrapped_dek"`  // base64, AES-GCM under the master key
	MasterKeyID      string      `json:"master_key_id"`
	SignerPublicKey  string      `json:"signer_public_key"` // base64 Ed25519
	RetainUntil      *time.Time  `json:"retain_until,omitempty"`
	ObjectLockActive bool        `json:"object_lock,omitempty"`
}

// Signed is the stored envelope.
type Signed struct {
	Manifest  json.RawMessage `json:"manifest"`
	Signature string          `json:"signature"` // base64 Ed25519 over Manifest bytes
}

// Sign serialises and signs m.
func Sign(m *Manifest, key ed25519.PrivateKey) ([]byte, error) {
	m.SignerPublicKey = base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	body, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	// Marshal (not MarshalIndent): the embedded manifest must stay byte-for-
	// byte identical to the signed body.
	return json.Marshal(Signed{Manifest: body, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, body))})
}

// ErrUntrustedSigner is returned when a pinned signer does not match.
var ErrUntrustedSigner = errors.New("backup manifest is not signed by the expected key")

// VerifyManifest checks the signature. When pinned is non-nil the manifest
// must be signed by exactly that key (restore on a clean node should pin
// the key recorded when the backup was configured).
func VerifyManifest(b []byte, pinned ed25519.PublicKey) (*Manifest, error) {
	var s Signed
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(s.Manifest, &m); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	pk, err := base64.StdEncoding.DecodeString(m.SignerPublicKey)
	if err != nil || len(pk) != ed25519.PublicKeySize {
		return nil, errors.New("manifest: bad signer key")
	}
	if pinned != nil && !pinned.Equal(ed25519.PublicKey(pk)) {
		return nil, ErrUntrustedSigner
	}
	sig, err := base64.StdEncoding.DecodeString(s.Signature)
	if err != nil || !ed25519.Verify(pk, s.Manifest, sig) {
		return nil, errors.New("manifest signature invalid")
	}
	if m.Format != Format {
		return nil, fmt.Errorf("unsupported backup format %q", m.Format)
	}
	return &m, nil
}

func decodeB64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }
