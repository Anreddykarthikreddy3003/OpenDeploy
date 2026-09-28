// Package backup implements encrypted, signed, off-host backups and clean
// node restore (PRD §19, SC-21, ST-11).
//
// Key hierarchy: a per-backup random data key (DEK) encrypts the archive
// with chunked AES-256-GCM; the DEK is wrapped by the operator's backup
// master key, which is stored separately from the node and never inside a
// backup. The manifest (hashes, sizes, wrapped DEK) is signed with the
// node's Ed25519 backup key. Without the master key a backup reveals only
// sizes and timestamps.
package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// ChunkSize is the plaintext size of each sealed chunk.
const ChunkSize = 1 << 20

// ErrTampered reports any authentication failure while decrypting.
var ErrTampered = errors.New("backup data failed authentication (wrong key, corrupted or tampered)")

// MasterKey is the 256-bit backup master key.
type MasterKey [32]byte

// ID is a short fingerprint that lets restore pick the right key.
func (k MasterKey) ID() string {
	h := sha256.Sum256(append([]byte("opendeploy-backup-master:"), k[:]...))
	return hex.EncodeToString(h[:8])
}

// LoadOrCreateMasterKey reads a hex key file, creating it (0600) if absent.
func LoadOrCreateMasterKey(path string) (MasterKey, bool, error) {
	var k MasterKey
	if b, err := os.ReadFile(path); err == nil {
		raw, err := hex.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(raw) != 32 {
			return k, false, fmt.Errorf("backup master key %s: expected 64 hex characters", path)
		}
		copy(k[:], raw)
		return k, false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return k, false, err
	}
	if _, err := rand.Read(k[:]); err != nil {
		return k, false, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(k[:])+"\n"), 0o600); err != nil {
		return k, false, err
	}
	return k, true, nil
}

// ParseMasterKey parses a hex key.
func ParseMasterKey(s string) (MasterKey, error) {
	var k MasterKey
	raw, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil || len(raw) != 32 {
		return k, errors.New("master key must be 64 hex characters")
	}
	copy(k[:], raw)
	return k, nil
}

func gcm(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// Wrap seals small data (a DEK) with key, bound to aad.
func Wrap(key, plain []byte, aad string) ([]byte, error) {
	a, err := gcm(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, a.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return a.Seal(nonce, nonce, plain, []byte(aad)), nil
}

// Unwrap opens data sealed by Wrap.
func Unwrap(key, sealed []byte, aad string) ([]byte, error) {
	a, err := gcm(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < a.NonceSize()+a.Overhead() {
		return nil, ErrTampered
	}
	out, err := a.Open(nil, sealed[:a.NonceSize()], sealed[a.NonceSize():], []byte(aad))
	if err != nil {
		return nil, ErrTampered
	}
	return out, nil
}

// chunkNonce derives the nonce of chunk i: 4 random prefix bytes + 8-byte
// counter. The AAD binds the backup id, the index and the final flag so
// chunks cannot be reordered, dropped, duplicated or truncated.
func chunkNonce(prefix []byte, i uint64) []byte {
	n := make([]byte, 12)
	copy(n, prefix[:4])
	binary.BigEndian.PutUint64(n[4:], i)
	return n
}

func chunkAAD(id string, i uint64, final bool) []byte {
	a := make([]byte, 0, len(id)+10)
	a = append(a, id...)
	a = binary.BigEndian.AppendUint64(a, i)
	if final {
		return append(a, 1)
	}
	return append(a, 0)
}

// Encryptor seals a plaintext stream in ChunkSize chunks.
type Encryptor struct {
	w      io.Writer
	aead   cipher.AEAD
	id     string
	prefix []byte
	buf    []byte
	i      uint64
	closed bool
	// Plain counts plaintext bytes.
	Plain int64
}

// NewEncryptor returns a writer that seals into w.
func NewEncryptor(w io.Writer, dek []byte, id string, noncePrefix []byte) (*Encryptor, error) {
	a, err := gcm(dek)
	if err != nil {
		return nil, err
	}
	if len(noncePrefix) != 4 {
		return nil, errors.New("nonce prefix must be 4 bytes")
	}
	return &Encryptor{w: w, aead: a, id: id, prefix: noncePrefix, buf: make([]byte, 0, ChunkSize)}, nil
}

func (e *Encryptor) Write(p []byte) (int, error) {
	if e.closed {
		return 0, errors.New("write after close")
	}
	n := 0
	for len(p) > 0 {
		room := ChunkSize - len(e.buf)
		take := min(room, len(p))
		e.buf = append(e.buf, p[:take]...)
		p = p[take:]
		n += take
		e.Plain += int64(take)
		// Flush only when more data follows, so the final chunk is
		// always emitted by Close (possibly empty).
		if len(e.buf) == ChunkSize && len(p) > 0 {
			if err := e.flush(false); err != nil {
				return n, err
			}
		}
	}
	return n, nil
}

func (e *Encryptor) flush(final bool) error {
	ct := e.aead.Seal(nil, chunkNonce(e.prefix, e.i), e.buf, chunkAAD(e.id, e.i, final))
	e.i++
	e.buf = e.buf[:0]
	_, err := e.w.Write(ct)
	return err
}

// Close writes the final chunk.
func (e *Encryptor) Close() error {
	if e.closed {
		return nil
	}
	e.closed = true
	return e.flush(true)
}

// Decryptor opens a stream written by Encryptor. It fails on the first
// unauthenticated chunk and on truncation (missing final chunk).
type Decryptor struct {
	r      io.Reader
	aead   cipher.AEAD
	id     string
	prefix []byte
	i      uint64
	buf    []byte
	next   []byte // one sealed chunk of lookahead to detect the final one
	done   bool
	err    error
}

// NewDecryptor returns a reader of the plaintext.
func NewDecryptor(r io.Reader, dek []byte, id string, noncePrefix []byte) (*Decryptor, error) {
	a, err := gcm(dek)
	if err != nil {
		return nil, err
	}
	return &Decryptor{r: r, aead: a, id: id, prefix: noncePrefix}, nil
}

func (d *Decryptor) readSealed() ([]byte, error) {
	b := make([]byte, ChunkSize+d.aead.Overhead())
	n, err := io.ReadFull(d.r, b)
	switch {
	case err == nil:
		return b, nil
	case errors.Is(err, io.ErrUnexpectedEOF):
		return b[:n], nil
	case errors.Is(err, io.EOF):
		return nil, io.EOF
	}
	return nil, err
}

func (d *Decryptor) Read(p []byte) (int, error) {
	for len(d.buf) == 0 {
		if d.err != nil {
			return 0, d.err
		}
		if d.done {
			return 0, io.EOF
		}
		cur := d.next
		if cur == nil {
			c, err := d.readSealed()
			if err != nil {
				if errors.Is(err, io.EOF) {
					d.err = ErrTampered // stream ended without a final chunk
				} else {
					d.err = err
				}
				continue
			}
			cur = c
		}
		nxt, err := d.readSealed()
		final := errors.Is(err, io.EOF)
		if err != nil && !final {
			d.err = err
			continue
		}
		d.next = nxt
		pt, oerr := d.aead.Open(nil, chunkNonce(d.prefix, d.i), cur, chunkAAD(d.id, d.i, final))
		if oerr != nil {
			d.err = ErrTampered
			continue
		}
		d.i++
		d.buf = pt
		if final {
			d.done = true
		}
	}
	n := copy(p, d.buf)
	d.buf = d.buf[n:]
	return n, nil
}
