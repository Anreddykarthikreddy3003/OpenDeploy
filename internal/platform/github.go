package platform

import (
	"context"
	"errors"
	"strconv"
	"sync"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/config"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/git/github"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/secrets"
)

// Secret names used for GitHub App credentials (instance scope in secretd).
const (
	SecretGitHubAppID      = "opendeploy.github.app_id"
	SecretGitHubSlug       = "opendeploy.github.app_slug"
	SecretGitHubPrivateKey = "opendeploy.github.private_key"
	SecretGitHubWebhook    = "opendeploy.github.webhook_secret"
)

// ErrGitHubNotConfigured is returned before a GitHub App is connected.
var ErrGitHubNotConfigured = errors.New("GitHub App is not configured; connect GitHub first")

// GitHubProvider lazily loads the GitHub App.
type GitHubProvider struct {
	Node    *config.Node
	Secrets secrets.Broker

	mu      sync.Mutex
	app     *github.App
	webhook []byte
	slug    string
	// Override for tests.
	APIURL string
}

// App returns the configured app.
func (g *GitHubProvider) App(ctx context.Context) (*github.App, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.app != nil {
		return g.app, nil
	}
	if err := g.loadLocked(ctx); err != nil {
		return nil, err
	}
	return g.app, nil
}

// WebhookSecret returns the webhook HMAC secret.
func (g *GitHubProvider) WebhookSecret(ctx context.Context) ([]byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.webhook == nil {
		if err := g.loadLocked(ctx); err != nil {
			return nil, err
		}
	}
	return g.webhook, nil
}

// Slug returns the app slug (for install links).
func (g *GitHubProvider) Slug(ctx context.Context) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.app == nil {
		_ = g.loadLocked(ctx)
	}
	return g.slug
}

// Reset drops cached credentials (after manifest registration).
func (g *GitHubProvider) Reset() {
	g.mu.Lock()
	g.app, g.webhook, g.slug = nil, nil, ""
	g.mu.Unlock()
}

// SetForTest injects an app and webhook secret.
func (g *GitHubProvider) SetForTest(app *github.App, webhook []byte) {
	g.mu.Lock()
	g.app, g.webhook = app, webhook
	g.mu.Unlock()
}

func (g *GitHubProvider) loadLocked(ctx context.Context) error {
	api := g.APIURL
	if api == "" {
		api = g.Node.GitHub.APIURL
	}
	// 1. Node configuration files.
	c := g.Node.GitHub
	if c.AppID != 0 && c.PrivateKeyFile != "" {
		pem, err := config.ReadSecretFile(c.PrivateKeyFile)
		if err != nil {
			return err
		}
		key, err := github.ParsePrivateKey(pem)
		if err != nil {
			return err
		}
		// No webhook_secret_file: an App without a webhook (F-8). A file
		// that is set but unreadable is still an error.
		wh := []byte{}
		if c.WebhookSecretFile != "" {
			if wh, err = config.ReadSecretFile(c.WebhookSecretFile); err != nil {
				return err
			}
		}
		g.app, g.webhook, g.slug = github.NewApp(c.AppID, key, api), noNil(wh), c.AppSlug
		return nil
	}
	// 2. Credentials registered through the manifest flow (secretd).
	if g.Secrets == nil {
		return ErrGitHubNotConfigured
	}
	metas, err := g.Secrets.List(ctx, secrets.ListReq{Scope: secrets.ScopeInstance})
	if err != nil {
		return err
	}
	byName := map[string]secrets.Meta{}
	for _, m := range metas {
		byName[m.Name] = m
	}
	reveal := func(name string) (string, error) {
		m, ok := byName[name]
		if !ok {
			return "", ErrGitHubNotConfigured
		}
		if !m.Sensitive {
			return m.Preview, nil
		}
		r, err := g.Secrets.Reveal(ctx, secrets.RevealReq{ID: m.ID, Actor: secrets.Actor{Type: "service", ID: "platformd"}, Reason: "load GitHub App credentials"})
		if err != nil {
			return "", err
		}
		return r.Value, nil
	}
	idStr, err := reveal(SecretGitHubAppID)
	if err != nil {
		return err
	}
	appID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		return err
	}
	pem, err := reveal(SecretGitHubPrivateKey)
	if err != nil {
		return err
	}
	key, err := github.ParsePrivateKey([]byte(pem))
	if err != nil {
		return err
	}
	// An App registered without a webhook (the node was not reachable from
	// GitHub, F-8) has an empty or absent webhook secret. That is a valid
	// state: the App works, and HandleGitHubWebhook refuses every delivery.
	wh, err := reveal(SecretGitHubWebhook)
	if err != nil && !errors.Is(err, ErrGitHubNotConfigured) {
		return err
	}
	slug, _ := reveal(SecretGitHubSlug)
	g.app, g.webhook, g.slug = github.NewApp(appID, key, api), noNil([]byte(wh)), slug
	return nil
}

// noNil keeps an empty webhook secret distinguishable from "not loaded yet"
// (nil), so WebhookSecret does not reload on every delivery.
func noNil(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}
