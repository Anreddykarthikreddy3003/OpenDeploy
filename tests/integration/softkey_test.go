package integration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// softKey is a software FIDO2 authenticator (ES256, "none" attestation)
// used to drive the real WebAuthn ceremonies end to end.
type softKey struct {
	t      *testing.T
	key    *ecdsa.PrivateKey
	credID []byte
	count  uint32
	origin string
	rpID   string
}

var b64 = base64.RawURLEncoding

func newSoftKey(t *testing.T, origin, rpID string) *softKey {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id := make([]byte, 32)
	_, _ = rand.Read(id)
	return &softKey{t: t, key: k, credID: id, origin: origin, rpID: rpID}
}

func (k *softKey) clientData(typ, challenge string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": k.origin, "crossOrigin": false})
	return b
}

func (k *softKey) authData(flags byte, attested []byte) []byte {
	h := sha256.Sum256([]byte(k.rpID))
	out := append([]byte{}, h[:]...)
	out = append(out, flags)
	c := make([]byte, 4)
	binary.BigEndian.PutUint32(c, k.count)
	out = append(out, c...)
	return append(out, attested...)
}

func challengeOf(t *testing.T, opts map[string]any) string {
	pk, ok := opts["publicKey"].(map[string]any)
	if !ok {
		t.Fatalf("options without publicKey: %v", opts)
	}
	return pk["challenge"].(string)
}

// create answers navigator.credentials.create().
func (k *softKey) create(opts map[string]any) json.RawMessage {
	ch := challengeOf(k.t, opts)
	em, _ := cbor.CoreDetEncOptions().EncMode()
	x, y := k.key.PublicKey.X.FillBytes(make([]byte, 32)), k.key.PublicKey.Y.FillBytes(make([]byte, 32))
	cose, err := em.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
	if err != nil {
		k.t.Fatal(err)
	}
	att := make([]byte, 16) // AAGUID
	l := make([]byte, 2)
	binary.BigEndian.PutUint16(l, uint16(len(k.credID)))
	att = append(append(append(att, l...), k.credID...), cose...)
	ad := k.authData(0x01|0x04|0x40, att) // UP | UV | AT
	ao, _ := em.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": ad})
	resp, _ := json.Marshal(map[string]any{"id": b64.EncodeToString(k.credID), "rawId": b64.EncodeToString(k.credID), "type": "public-key",
		"response": map[string]any{"clientDataJSON": b64.EncodeToString(k.clientData("webauthn.create", ch)), "attestationObject": b64.EncodeToString(ao)}})
	return resp
}

// get answers navigator.credentials.get(); counterDelta < 0 simulates a
// cloned authenticator replaying an older counter.
func (k *softKey) get(opts map[string]any, userID string, counterDelta int) json.RawMessage {
	ch := challengeOf(k.t, opts)
	k.count = uint32(int(k.count) + counterDelta)
	ad := k.authData(0x01|0x04, nil)
	cd := k.clientData("webauthn.get", ch)
	h := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), h[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, k.key, digest[:])
	if err != nil {
		k.t.Fatal(err)
	}
	resp, _ := json.Marshal(map[string]any{"id": b64.EncodeToString(k.credID), "rawId": b64.EncodeToString(k.credID), "type": "public-key",
		"response": map[string]any{"clientDataJSON": b64.EncodeToString(cd), "authenticatorData": b64.EncodeToString(ad),
			"signature": b64.EncodeToString(sig), "userHandle": b64.EncodeToString([]byte(userID))}})
	return resp
}
