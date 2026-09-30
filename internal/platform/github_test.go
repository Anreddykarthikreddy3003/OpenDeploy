package platform

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/audit"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/config"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/git/github"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/secrets"
)

// memBroker is an in-memory instance-scope secret broker.
type memBroker struct{ vals map[string]string }

func (b *memBroker) Set(_ context.Context, r secrets.SetReq) (*secrets.Meta, error) {
	b.vals[r.Ref.Name] = r.Value
	return &secrets.Meta{ID: r.Ref.Name, Ref: r.Ref, Sensitive: r.Sensitive}, nil
}
func (b *memBroker) List(context.Context, secrets.ListReq) ([]secrets.Meta, error) {
	var out []secrets.Meta
	for n := range b.vals {
		out = append(out, secrets.Meta{ID: n, Ref: secrets.Ref{Scope: secrets.ScopeInstance, Name: n}, Sensitive: true})
	}
	return out, nil
}
func (b *memBroker) Delete(context.Context, secrets.DeleteReq) error               { return nil }
func (b *memBroker) DeleteProject(context.Context, secrets.DeleteProjectReq) error { return nil }
func (b *memBroker) Reveal(_ context.Context, r secrets.RevealReq) (*secrets.RevealResp, error) {
	v, ok := b.vals[r.ID]
	if !ok {
		return nil, secrets.ErrNotFound
	}
	return &secrets.RevealResp{Value: v}, nil
}
func (b *memBroker) Resolve(context.Context, secrets.ResolveReq) (*secrets.Resolved, error) {
	return nil, secrets.ErrDenied
}

func testKeyPEM(t *testing.T) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}))
}

const testPush = `{"ref":"refs/heads/main","after":"7fd1a60b01f91b314f59955a4e4d4e80d8edf11d","repository":{"id":99},"installation":{"id":7}}`

// F-8: an App registered without a webhook has no webhook secret (GitHub
// returns null, stored as empty, or the secret is absent). The App must
// still load, so repositories can be listed and imported, and
// /webhooks/github must refuse every delivery: unsigned, signed with an
// empty key, or signed with any other key.
func TestGitHubAppWithoutWebhookSecret(t *testing.T) {
	key := testKeyPEM(t)
	cases := map[string]map[string]string{
		"empty secret (webhook_secret null)": {SecretGitHubAppID: "42", SecretGitHubSlug: "od", SecretGitHubPrivateKey: key, SecretGitHubWebhook: ""},
		"no secret stored":                   {SecretGitHubAppID: "42", SecretGitHubSlug: "od", SecretGitHubPrivateKey: key},
	}
	for name, vals := range cases {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			n := &config.Node{}
			gh := &GitHubProvider{Node: n, Secrets: &memBroker{vals: vals}, APIURL: "http://127.0.0.1:1"}
			app, err := gh.App(ctx)
			if err != nil {
				t.Fatalf("App without a webhook secret: %v", err)
			}
			if app.ID != 42 || gh.Slug(ctx) != "od" {
				t.Fatalf("app %d slug %q", app.ID, gh.Slug(ctx))
			}
			sec, err := gh.WebhookSecret(ctx)
			if err != nil || len(sec) != 0 {
				t.Fatalf("webhook secret %q, %v", sec, err)
			}
			assertWebhooksRefused(t, &Platform{Deps: Deps{Node: n, Audit: audit.Nop{}, GitHub: gh}})
		})
	}
}

// The same with credentials from node.yaml and no github.webhook_secret_file.
func TestGitHubAppFromConfigWithoutWebhookSecretFile(t *testing.T) {
	dir := t.TempDir()
	kp := filepath.Join(dir, "app.pem")
	if err := os.WriteFile(kp, []byte(testKeyPEM(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	n := &config.Node{}
	n.GitHub.AppID, n.GitHub.PrivateKeyFile = 42, kp
	gh := &GitHubProvider{Node: n, APIURL: "http://127.0.0.1:1"}
	if _, err := gh.App(context.Background()); err != nil {
		t.Fatalf("App without webhook_secret_file: %v", err)
	}
	assertWebhooksRefused(t, &Platform{Deps: Deps{Node: n, Audit: audit.Nop{}, GitHub: gh}})

	// A configured secret file that cannot be read is still an error.
	n.GitHub.WebhookSecretFile = filepath.Join(dir, "missing")
	gh = &GitHubProvider{Node: n, APIURL: "http://127.0.0.1:1"}
	if _, err := gh.App(context.Background()); err == nil {
		t.Fatal("unreadable webhook_secret_file accepted")
	}
}

func assertWebhooksRefused(t *testing.T, p *Platform) {
	t.Helper()
	body := []byte(testPush)
	for name, sig := range map[string]string{
		"unsigned":         "",
		"empty key":        github.Sign(nil, body),
		"empty key (ping)": github.Sign([]byte{}, []byte(`{}`)),
		"other key":        github.Sign([]byte("guess"), body),
		"malformed":        "sha256=zz",
	} {
		for _, event := range []string{"push", "ping"} {
			b := body
			if name == "empty key (ping)" {
				b = []byte(`{}`)
			}
			res := p.HandleGitHubWebhook(context.Background(), event, "72d3162e-cc78-11e3-81ab-4c9367dc0958", sig, "192.0.2.1", b)
			if res.Status != 401 {
				t.Errorf("%s %s: status %d (%s), want 401", name, event, res.Status, res.Outcome)
			}
		}
	}
}
