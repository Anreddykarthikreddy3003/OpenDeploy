package relay

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"
)

// Registry errors.
var (
	ErrTokenInvalid  = errors.New("enrollment token invalid, expired or already used")
	ErrInstanceTaken = errors.New("instance id belongs to another tenant")
	ErrRevoked       = errors.New("instance credential revoked")
	ErrUnknown       = errors.New("unknown instance")
)

// InstanceRecord is one enrolled instance.
type InstanceRecord struct {
	Tenant    string    `json:"tenant"`
	Instance  string    `json:"instance"`
	CreatedAt time.Time `json:"created_at"`
	Revoked   bool      `json:"revoked"`
	RevokedAt time.Time `json:"revoked_at,omitempty"`
	// CertsValidAfter rejects every certificate issued before it (credential
	// rotation after suspected theft).
	CertsValidAfter time.Time `json:"certs_valid_after"`
}

type tokenRecord struct {
	ID        string    `json:"id"`
	Hash      string    `json:"hash"`
	Tenant    string    `json:"tenant"`
	Instance  string    `json:"instance"`
	ExpiresAt time.Time `json:"expires_at"`
	UsedAt    time.Time `json:"used_at,omitempty"`
}

type registryData struct {
	Instances map[string]*InstanceRecord `json:"instances"`
	Tokens    map[string]*tokenRecord    `json:"tokens"`
}

// Registry is the relay's durable instance/credential state. The admin CLI
// and the running server share it through a locked JSON file.
type Registry struct {
	path  string
	mu    sync.Mutex
	data  registryData
	mtime time.Time
	size  int64
}

// OpenRegistry loads (or initialises) the registry at path.
func OpenRegistry(path string) (*Registry, error) {
	r := &Registry{path: path}
	if err := r.update(func(*registryData) error { return nil }); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Registry) load() error {
	fi, err := os.Stat(r.path)
	if errors.Is(err, os.ErrNotExist) {
		r.data = registryData{Instances: map[string]*InstanceRecord{}, Tokens: map[string]*tokenRecord{}}
		return nil
	}
	if err != nil {
		return err
	}
	if fi.ModTime().Equal(r.mtime) && fi.Size() == r.size && r.data.Instances != nil {
		return nil
	}
	b, err := os.ReadFile(r.path)
	if err != nil {
		return err
	}
	var d registryData
	if err := json.Unmarshal(b, &d); err != nil {
		return fmt.Errorf("relay registry corrupt: %w", err)
	}
	if d.Instances == nil {
		d.Instances = map[string]*InstanceRecord{}
	}
	if d.Tokens == nil {
		d.Tokens = map[string]*tokenRecord{}
	}
	r.data, r.mtime, r.size = d, fi.ModTime(), fi.Size()
	return nil
}

// update runs fn over fresh on-disk state under an exclusive file lock and
// persists the result atomically.
func (r *Registry) update(fn func(*registryData) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	unlock, err := lockFile(r.path + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
	r.mtime = time.Time{}
	if err := r.load(); err != nil {
		return err
	}
	if err := fn(&r.data); err != nil {
		return err
	}
	b, err := json.MarshalIndent(r.data, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileAtomic(r.path, b, 0o600); err != nil {
		return err
	}
	if fi, err := os.Stat(r.path); err == nil {
		r.mtime, r.size = fi.ModTime(), fi.Size()
	}
	return nil
}

func (r *Registry) view() (registryData, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.load(); err != nil {
		return registryData{}, err
	}
	return r.data, nil
}

// CreateToken allocates a one-time enrollment token for tenant/instance.
// Re-enrolling an existing instance (same tenant) rotates its credential:
// every certificate issued before now stops working.
func (r *Registry) CreateToken(ca *CA, tenant, instance string, ttl time.Duration) (EnrollToken, error) {
	if !ValidID(tenant) || !ValidID(instance) {
		return EnrollToken{}, errors.New("tenant and instance must be DNS labels (a-z, 0-9, '-', 2-40 chars)")
	}
	tok := EnrollToken{ID: randHex(8), Secret: randHex(32), CAFingerprint: ca.Fingerprint()}
	err := r.update(func(d *registryData) error {
		if in, ok := d.Instances[instance]; ok && in.Tenant != tenant {
			return ErrInstanceTaken
		}
		d.Tokens[tok.ID] = &tokenRecord{ID: tok.ID, Hash: hashSecret(tok.Secret), Tenant: tenant, Instance: instance, ExpiresAt: time.Now().Add(ttl)}
		// Garbage-collect used/expired tokens.
		for id, t := range d.Tokens {
			if !t.UsedAt.IsZero() || time.Now().After(t.ExpiresAt.Add(24*time.Hour)) {
				delete(d.Tokens, id)
			}
		}
		return nil
	})
	return tok, err
}

// Redeem consumes a token (single use) and registers the instance.
func (r *Registry) Redeem(tok EnrollToken) (Identity, error) {
	var id Identity
	err := r.update(func(d *registryData) error {
		t, ok := d.Tokens[tok.ID]
		if !ok || !t.UsedAt.IsZero() || time.Now().After(t.ExpiresAt) || !equalHash(t.Hash, hashSecret(tok.Secret)) {
			return ErrTokenInvalid
		}
		t.UsedAt = time.Now()
		in, ok := d.Instances[t.Instance]
		if ok && in.Tenant != t.Tenant {
			return ErrInstanceTaken
		}
		cut := time.Now().Truncate(time.Second).Add(time.Second)
		if !ok {
			in = &InstanceRecord{Tenant: t.Tenant, Instance: t.Instance, CreatedAt: time.Now()}
			d.Instances[t.Instance] = in
		}
		in.Revoked, in.RevokedAt, in.CertsValidAfter = false, time.Time{}, cut
		id = Identity{Tenant: t.Tenant, Instance: t.Instance}
		return nil
	})
	if err == nil {
		// Certificates for the new enrollment are issued after the cut.
		time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(time.Second)))
	}
	return id, err
}

// Revoke disables an instance immediately (live tunnels are closed by the
// server on its next registry check).
func (r *Registry) Revoke(instance string) error {
	return r.update(func(d *registryData) error {
		in, ok := d.Instances[instance]
		if !ok {
			return ErrUnknown
		}
		in.Revoked, in.RevokedAt = true, time.Now()
		return nil
	})
}

// Authorize checks a verified client certificate against the registry.
func (r *Registry) Authorize(c *x509.Certificate) (Identity, error) {
	id, err := IdentityFromCert(c)
	if err != nil {
		return Identity{}, err
	}
	d, err := r.view()
	if err != nil {
		return Identity{}, err
	}
	in, ok := d.Instances[id.Instance]
	switch {
	case !ok:
		return id, ErrUnknown
	case in.Tenant != id.Tenant:
		return id, fmt.Errorf("%w: tenant mismatch", ErrRevoked)
	case in.Revoked:
		return id, ErrRevoked
	case c.NotBefore.Add(5 * time.Minute).Before(in.CertsValidAfter):
		return id, fmt.Errorf("%w: certificate predates credential rotation", ErrRevoked)
	}
	return id, nil
}

// Check verifies an already-authenticated identity is still enrolled and
// not revoked (used for renewals over a live tunnel).
func (r *Registry) Check(id Identity) error {
	d, err := r.view()
	if err != nil {
		return err
	}
	in, ok := d.Instances[id.Instance]
	switch {
	case !ok:
		return ErrUnknown
	case in.Tenant != id.Tenant || in.Revoked:
		return ErrRevoked
	}
	return nil
}

// Instances lists enrolled instances.
func (r *Registry) Instances() ([]InstanceRecord, error) {
	d, err := r.view()
	if err != nil {
		return nil, err
	}
	out := make([]InstanceRecord, 0, len(d.Instances))
	for _, in := range d.Instances {
		out = append(out, *in)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Instance < out[j].Instance })
	return out, nil
}
