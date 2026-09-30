// Package auth provides password hashing (Argon2id), TOTP MFA, recovery
// codes, token helpers and the RBAC policy (PRD §15, SC-11).
package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters (OWASP 2024 guidance: m=19MiB,t=2 minimum; we use more).
const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 2
	argonKeyLen  = 32
	saltLen      = 16
	// MinPasswordLen is the minimum accepted password length.
	MinPasswordLen = 12
	MaxPasswordLen = 256
)

// HashPassword returns a PHC-formatted Argon2id hash.
func HashPassword(pw string) (string, error) {
	if err := CheckPasswordPolicy(pw); err != nil {
		return "", err
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// CheckPasswordPolicy enforces length bounds.
func CheckPasswordPolicy(pw string) error {
	if len(pw) < MinPasswordLen {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLen)
	}
	if len(pw) > MaxPasswordLen {
		return fmt.Errorf("password must be at most %d characters", MaxPasswordLen)
	}
	return nil
}

// dummyHash is verified against when the user does not exist, so login
// timing does not reveal account existence.
var dummyHash, _ = HashPassword("opendeploy-dummy-password")

// VerifyPassword checks pw against a PHC Argon2id hash in constant time.
func VerifyPassword(hash, pw string) bool {
	if hash == "" {
		hash = dummyHash
		pw = pw + "\x00never"
	}
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	if m > 1<<20 || t > 20 || p > 16 || m < 8*uint32(p) || t == 0 || p == 0 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) < 16 || len(salt) < 8 { // an empty key would match anything
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// NewToken returns a random URL-safe token with prefix and its SHA-256 hex
// digest (the digest is what gets stored).
func NewToken(prefix string, n int) (token, digest string) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	token = prefix + base64.RawURLEncoding.EncodeToString(b)
	return token, HashToken(token)
}

// HashToken hashes a bearer/session token for storage.
func HashToken(tok string) string {
	s := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(s[:])
}

// ---------------------------------------------------------------- TOTP (RFC 6238)

// TOTPPeriod is the time step.
const TOTPPeriod = 30

// NewTOTPSecret returns a random 160-bit base32 secret.
func NewTOTPSecret() string {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

// TOTPURI returns an otpauth:// URI for authenticator apps.
func TOTPURI(issuer, account, secret string) string {
	v := url.Values{"secret": {secret}, "issuer": {issuer}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	return "otpauth://totp/" + url.PathEscape(issuer+":"+account) + "?" + v.Encode()
}

func hotp(key []byte, counter uint64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := (binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff) % 1000000
	return fmt.Sprintf("%06d", code)
}

// TOTPCode computes the code for time t (tests / enrolment display).
func TOTPCode(secret string, t time.Time) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", err
	}
	return hotp(key, uint64(t.Unix())/TOTPPeriod), nil
}

// VerifyTOTP checks code within ±1 step and rejects steps <= lastStep
// (replay protection). It returns the matched step.
func VerifyTOTP(secret, code string, now time.Time, lastStep int64) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return 0, false
	}
	if _, err := strconv.Atoi(code); err != nil {
		return 0, false
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return 0, false
	}
	cur := now.Unix() / TOTPPeriod
	for _, d := range []int64{0, -1, 1} {
		step := cur + d
		if step <= lastStep {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(hotp(key, uint64(step))), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

// NewRecoveryCodes returns n human-friendly one-time codes and their hashes.
func NewRecoveryCodes(n int) (codes, hashes []string) {
	for i := 0; i < n; i++ {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			panic(err)
		}
		c := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))[:12]
		c = c[:4] + "-" + c[4:8] + "-" + c[8:]
		codes = append(codes, c)
		hashes = append(hashes, HashToken(normalizeRecovery(c)))
	}
	return
}

// HashRecoveryCode hashes user input for comparison.
func HashRecoveryCode(c string) string { return HashToken(normalizeRecovery(c)) }

func normalizeRecovery(c string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(c), "-", ""))
}

// ---------------------------------------------------------------- sealing

// Sealer encrypts small values (TOTP seeds, WebAuthn data) with a local key
// owned by platformd.
type Sealer struct{ key []byte }

// NewSealer creates a sealer from a 32-byte key.
func NewSealer(key []byte) (*Sealer, error) {
	if len(key) != 32 {
		return nil, errors.New("sealer key must be 32 bytes")
	}
	return &Sealer{key: key}, nil
}

func (s *Sealer) Seal(plain []byte, aad string) ([]byte, error) {
	blk, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}
	g, _ := cipher.NewGCM(blk)
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return append(nonce, g.Seal(nil, nonce, plain, []byte(aad))...), nil
}

func (s *Sealer) Open(ct []byte, aad string) ([]byte, error) {
	blk, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}
	g, _ := cipher.NewGCM(blk)
	if len(ct) < g.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	return g.Open(nil, ct[:g.NonceSize()], ct[g.NonceSize():], []byte(aad))
}
