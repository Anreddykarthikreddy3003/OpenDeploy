package github

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// The webhook endpoint is internet-facing: signature checking and event
// parsing must never panic, and only a correct HMAC may verify.
func FuzzVerifySignature(f *testing.F) {
	secret := []byte("webhook-secret")
	body := []byte(`{"ref":"refs/heads/main"}`)
	m := hmac.New(sha256.New, secret)
	m.Write(body)
	good := "sha256=" + hex.EncodeToString(m.Sum(nil))
	f.Add(body, good)
	f.Add(body, "sha256=")
	f.Add([]byte{}, "sha1=abc")
	f.Fuzz(func(t *testing.T, b []byte, header string) {
		err := VerifySignature(secret, b, header)
		m := hmac.New(sha256.New, secret)
		m.Write(b)
		want := "sha256=" + hex.EncodeToString(m.Sum(nil))
		// Hex is case-insensitive: only the same MAC may verify.
		if err == nil && !strings.EqualFold(header, want) {
			t.Fatalf("forged signature %q accepted", header)
		}
	})
}

func FuzzParseEvent(f *testing.F) {
	for _, s := range []struct{ name, body string }{
		{"push", `{"ref":"refs/heads/main","after":"` + "0123456789abcdef0123456789abcdef01234567" + `","repository":{"id":1,"full_name":"a/b","clone_url":"https://github.com/a/b.git"},"installation":{"id":2}}`},
		{"pull_request", `{"action":"opened","number":3,"pull_request":{"head":{"sha":"x","ref":"f","repo":{"fork":true,"full_name":"c/b"}},"base":{"ref":"main"}},"repository":{"id":1},"installation":{"id":2}}`},
		{"installation", `{"action":"deleted","installation":{"id":2}}`},
		{"ping", `{}`},
	} {
		f.Add(s.name, "72d3162e-cc78-11e3-81ab-4c9367dc0958", []byte(s.body))
	}
	f.Fuzz(func(t *testing.T, name, delivery string, body []byte) {
		ev, err := ParseEvent(name, delivery, body)
		if err == nil && ev == nil {
			t.Fatal("nil event without error")
		}
	})
}
