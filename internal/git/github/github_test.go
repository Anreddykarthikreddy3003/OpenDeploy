package github

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestJWT(t *testing.T) {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	a := NewApp(1234, k, "")
	j, err := a.JWT(time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(j, ".")
	if len(parts) != 3 {
		t.Fatal(j)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&k.PublicKey, crypto.SHA256, sum[:], sig); err != nil {
		t.Fatal(err)
	}
	cb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var c map[string]any
	_ = json.Unmarshal(cb, &c)
	if c["iss"] != "1234" || c["exp"].(float64)-c["iat"].(float64) > 600 {
		t.Fatalf("%v", c)
	}
}

func TestVerifySignature(t *testing.T) {
	secret := []byte("s3cret")
	body := []byte(`{"a":1}`)
	good := Sign(secret, body)
	if err := VerifySignature(secret, body, good); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"missing":   "",
		"sha1":      "sha1=abcd",
		"wrong":     Sign([]byte("other"), body),
		"truncated": good[:20],
		"nonhex":    "sha256=zz",
	}
	for name, h := range cases {
		if VerifySignature(secret, body, h) == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if VerifySignature(secret, []byte(`{"a":2}`), good) == nil {
		t.Error("modified body accepted")
	}
	if VerifySignature(nil, body, Sign(nil, body)) == nil {
		t.Error("empty secret accepted")
	}
}

const pushFixture = `{"ref":"refs/heads/main","before":"0000000000000000000000000000000000000000","after":"7fd1a60b01f91b314f59955a4e4d4e80d8edf11d",
"repository":{"id":99,"full_name":"o/r","clone_url":"https://github.com/o/r.git"},"installation":{"id":7},
"head_commit":{"id":"7fd1a60b01f91b314f59955a4e4d4e80d8edf11d","message":"hi","author":{"name":"A"}}}`

func TestParsePush(t *testing.T) {
	ev, err := ParseEvent("push", "72d3162e-cc78-11e3-81ab-4c9367dc0958", []byte(pushFixture))
	if err != nil {
		t.Fatal(err)
	}
	if b, ok := ev.Push.Branch(); !ok || b != "main" || ev.InstallationID() != 7 || ev.RepositoryID() != 99 {
		t.Fatalf("%+v", ev.Push)
	}
	if _, err := ParseEvent("push", "bad delivery!", []byte(pushFixture)); err == nil {
		t.Fatal("bad delivery accepted")
	}
	bad := strings.Replace(pushFixture, "7fd1a60b01f91b314f59955a4e4d4e80d8edf11d\",\n\"repository", "HEAD\",\n\"repository", 1)
	if _, err := ParseEvent("push", "72d3162e-cc78-11e3-81ab-4c9367dc0958", []byte(bad)); err == nil {
		t.Fatal("non-sha after accepted")
	}
}

func TestPRForkDetection(t *testing.T) {
	body := `{"action":"opened","number":3,"pull_request":{"number":3,"head":{"ref":"x","sha":"7fd1a60b01f91b314f59955a4e4d4e80d8edf11d","repo":{"id":5}},
	"base":{"ref":"main","repo":{"id":99}}},"repository":{"id":99},"installation":{"id":7}}`
	ev, err := ParseEvent("pull_request", "72d3162e-cc78-11e3-81ab-4c9367dc0958", []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if !ev.PullRequest.FromFork() {
		t.Fatal("fork not detected")
	}
	// A deleted head repo (id 0) is treated as a fork.
	body2 := strings.Replace(body, `"repo":{"id":5}`, `"repo":null`, 1)
	ev2, _ := ParseEvent("pull_request", "72d3162e-cc78-11e3-81ab-4c9367dc0958", []byte(body2))
	if !ev2.PullRequest.FromFork() {
		t.Fatal("missing head repo must be fork")
	}
}

func TestInstallationTokenRestricted(t *testing.T) {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	var gotBody map[string]any
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			w.WriteHeader(401)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]any{"token": "ghs_x", "expires_at": time.Now().Add(time.Hour)})
	}))
	defer srv.Close()
	a := NewApp(1, k, srv.URL)
	tok, err := a.InstallationToken(context.Background(), 7, []int64{99}, nil)
	if err != nil || tok.Token != "ghs_x" {
		t.Fatal(err)
	}
	perms := gotBody["permissions"].(map[string]any)
	if len(perms) != 1 || perms["contents"] != "read" {
		t.Fatalf("over-broad permissions: %v", perms)
	}
	if ids := gotBody["repository_ids"].([]any); len(ids) != 1 {
		t.Fatalf("token not repo-scoped: %v", gotBody)
	}
	_, _ = a.InstallationToken(context.Background(), 7, []int64{99}, nil)
	if calls != 1 {
		t.Fatal("token not cached")
	}
	a.ForgetInstallation(7)
	_, _ = a.InstallationToken(context.Background(), 7, []int64{99}, nil)
	if calls != 2 {
		t.Fatal("forget did not drop cache")
	}
}

func TestManifestMinimumPermissions(t *testing.T) {
	m := Manifest("od", "https://od.example.com", false)
	p := m["default_permissions"].(map[string]string)
	for k, v := range p {
		if v != "read" {
			t.Errorf("%s=%s exceeds read", k, v)
		}
	}
	if _, ok := p["administration"]; ok {
		t.Fatal("administration requested")
	}
}
