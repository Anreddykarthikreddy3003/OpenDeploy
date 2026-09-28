// Package github implements the GitHub App integration (PRD §6, SC-07):
// App JWT authentication, short-lived installation tokens restricted to the
// selected repository and minimum permissions, repository/branch lookups,
// optional check runs, and the one-click App Manifest registration flow.
//
// Installation tokens are cached in memory only until shortly before
// expiry and are never persisted as project credentials.
package github

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// App is an authenticated GitHub App.
type App struct {
	ID     int64
	Key    *rsa.PrivateKey
	APIURL string
	HTTP   *http.Client

	mu     sync.Mutex
	tokens map[string]Token
}

// Token is an installation access token.
type Token struct {
	Token     string            `json:"token"`
	ExpiresAt time.Time         `json:"expires_at"`
	Perms     map[string]string `json:"permissions"`
}

// ParsePrivateKey parses a PEM PKCS#1 or PKCS#8 RSA key.
func ParsePrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return nil, errors.New("github: invalid PEM private key")
	}
	if k, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("github: parse key: %w", err)
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("github: key is not RSA")
	}
	return rk, nil
}

// NewApp creates an App client.
func NewApp(id int64, key *rsa.PrivateKey, apiURL string) *App {
	if apiURL == "" {
		apiURL = "https://api.github.com"
	}
	return &App{ID: id, Key: key, APIURL: strings.TrimRight(apiURL, "/"), HTTP: &http.Client{Timeout: 30 * time.Second}, tokens: map[string]Token{}}
}

// JWT returns an app JWT valid for ~9 minutes (GitHub allows 10).
func (a *App) JWT(now time.Time) (string, error) {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, _ := json.Marshal(map[string]any{
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": strconv.FormatInt(a.ID, 10),
	})
	body := hdr + "." + base64.RawURLEncoding.EncodeToString(claims)
	sum := sha256.Sum256([]byte(body))
	sig, err := rsa.SignPKCS1v15(rand.Reader, a.Key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return body + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// APIError is a non-2xx GitHub response.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string { return fmt.Sprintf("github: %d %s", e.Status, e.Message) }

// IsNotFound reports whether err is a 404 (includes revoked access).
func IsNotFound(err error) bool {
	var e *APIError
	return errors.As(err, &e) && (e.Status == 404 || e.Status == 403 || e.Status == 401)
}

func (a *App) do(ctx context.Context, method, path, auth string, body, out any) (http.Header, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(b)
	}
	u := path
	if !strings.HasPrefix(path, "https://") && !strings.HasPrefix(path, "http://") {
		u = a.APIURL + path
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "OpenDeploy")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		var m struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(data, &m)
		return resp.Header, &APIError{Status: resp.StatusCode, Message: m.Message}
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return resp.Header, fmt.Errorf("github: decode %s: %w", path, err)
		}
	}
	return resp.Header, nil
}

func (a *App) appAuth() (string, error) {
	j, err := a.JWT(time.Now())
	if err != nil {
		return "", err
	}
	return "Bearer " + j, nil
}

// Installation describes an app installation.
type Installation struct {
	ID      int64 `json:"id"`
	Account struct {
		Login string `json:"login"`
		Type  string `json:"type"`
	} `json:"account"`
	RepositorySelection string            `json:"repository_selection"`
	Permissions         map[string]string `json:"permissions"`
	SuspendedAt         *time.Time        `json:"suspended_at"`
}

// GetInstallation fetches installation metadata (app-authenticated).
func (a *App) GetInstallation(ctx context.Context, id int64) (*Installation, error) {
	auth, err := a.appAuth()
	if err != nil {
		return nil, err
	}
	var inst Installation
	_, err = a.do(ctx, http.MethodGet, fmt.Sprintf("/app/installations/%d", id), auth, nil, &inst)
	return &inst, err
}

// ListInstallations lists installations of the app.
func (a *App) ListInstallations(ctx context.Context) ([]Installation, error) {
	auth, err := a.appAuth()
	if err != nil {
		return nil, err
	}
	var out []Installation
	for page := 1; page <= 20; page++ {
		var batch []Installation
		if _, err := a.do(ctx, http.MethodGet, fmt.Sprintf("/app/installations?per_page=100&page=%d", page), auth, nil, &batch); err != nil {
			return nil, err
		}
		out = append(out, batch...)
		if len(batch) < 100 {
			break
		}
	}
	return out, nil
}

// DefaultPermissions are the minimum permissions requested for source fetch
// (SC-07): contents read only. Metadata read is implicit.
var DefaultPermissions = map[string]string{"contents": "read"}

// InstallationToken returns a short-lived token restricted to repoIDs and
// perms. Tokens are cached until 5 minutes before expiry.
func (a *App) InstallationToken(ctx context.Context, installationID int64, repoIDs []int64, perms map[string]string) (Token, error) {
	if perms == nil {
		perms = DefaultPermissions
	}
	key := cacheKey(installationID, repoIDs, perms)
	a.mu.Lock()
	if t, ok := a.tokens[key]; ok && time.Until(t.ExpiresAt) > 5*time.Minute {
		a.mu.Unlock()
		return t, nil
	}
	a.mu.Unlock()
	auth, err := a.appAuth()
	if err != nil {
		return Token{}, err
	}
	body := map[string]any{"permissions": perms}
	if len(repoIDs) > 0 {
		body["repository_ids"] = repoIDs
	}
	var t Token
	if _, err := a.do(ctx, http.MethodPost, fmt.Sprintf("/app/installations/%d/access_tokens", installationID), auth, body, &t); err != nil {
		return Token{}, err
	}
	a.mu.Lock()
	a.tokens[key] = t
	a.mu.Unlock()
	return t, nil
}

// ForgetInstallation drops cached tokens (on revocation webhooks).
func (a *App) ForgetInstallation(installationID int64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	prefix := strconv.FormatInt(installationID, 10) + "|"
	for k := range a.tokens {
		if strings.HasPrefix(k, prefix) {
			delete(a.tokens, k)
		}
	}
}

func cacheKey(inst int64, repos []int64, perms map[string]string) string {
	var sb strings.Builder
	sb.WriteString(strconv.FormatInt(inst, 10))
	sb.WriteString("|")
	for _, r := range repos {
		sb.WriteString(strconv.FormatInt(r, 10))
		sb.WriteString(",")
	}
	keys := make([]string, 0, len(perms))
	for k := range perms {
		keys = append(keys, k)
	}
	sortStrings(keys)
	for _, k := range keys {
		sb.WriteString("|" + k + "=" + perms[k])
	}
	return sb.String()
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// Repository is repository metadata.
type Repository struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	FullName      string `json:"full_name"`
	Private       bool   `json:"private"`
	Fork          bool   `json:"fork"`
	CloneURL      string `json:"clone_url"`
	HTMLURL       string `json:"html_url"`
	DefaultBranch string `json:"default_branch"`
	Archived      bool   `json:"archived"`
	Owner         struct {
		Login string `json:"login"`
	} `json:"owner"`
}

// ListInstallationRepos lists repositories the installation can access.
func (a *App) ListInstallationRepos(ctx context.Context, installationID int64) ([]Repository, error) {
	t, err := a.InstallationToken(ctx, installationID, nil, map[string]string{"metadata": "read"})
	if err != nil {
		return nil, err
	}
	var out []Repository
	for page := 1; page <= 50; page++ {
		var resp struct {
			Repositories []Repository `json:"repositories"`
		}
		if _, err := a.do(ctx, http.MethodGet, fmt.Sprintf("/installation/repositories?per_page=100&page=%d", page), "token "+t.Token, nil, &resp); err != nil {
			return nil, err
		}
		out = append(out, resp.Repositories...)
		if len(resp.Repositories) < 100 {
			break
		}
	}
	return out, nil
}

// GetRepo returns a repository by ID using an installation token.
func (a *App) GetRepo(ctx context.Context, installationID, repoID int64) (*Repository, error) {
	t, err := a.InstallationToken(ctx, installationID, []int64{repoID}, map[string]string{"metadata": "read"})
	if err != nil {
		return nil, err
	}
	var r Repository
	_, err = a.do(ctx, http.MethodGet, fmt.Sprintf("/repositories/%d", repoID), "token "+t.Token, nil, &r)
	return &r, err
}

// Branch is a branch head.
type Branch struct {
	Name   string `json:"name"`
	Commit struct {
		SHA    string `json:"sha"`
		Commit struct {
			Message string `json:"message"`
			Author  struct {
				Name string `json:"name"`
			} `json:"author"`
		} `json:"commit"`
	} `json:"commit"`
}

// GetBranch returns the head commit of a branch.
func (a *App) GetBranch(ctx context.Context, installationID, repoID int64, branch string) (*Branch, error) {
	t, err := a.InstallationToken(ctx, installationID, []int64{repoID}, DefaultPermissions)
	if err != nil {
		return nil, err
	}
	var b Branch
	_, err = a.do(ctx, http.MethodGet, fmt.Sprintf("/repositories/%d/branches/%s", repoID, url.PathEscape(branch)), "token "+t.Token, nil, &b)
	return &b, err
}

// ListBranches lists branch names.
func (a *App) ListBranches(ctx context.Context, installationID, repoID int64) ([]string, error) {
	t, err := a.InstallationToken(ctx, installationID, []int64{repoID}, DefaultPermissions)
	if err != nil {
		return nil, err
	}
	var bs []Branch
	if _, err := a.do(ctx, http.MethodGet, fmt.Sprintf("/repositories/%d/branches?per_page=100", repoID), "token "+t.Token, nil, &bs); err != nil {
		return nil, err
	}
	out := make([]string, len(bs))
	for i, b := range bs {
		out[i] = b.Name
	}
	return out, nil
}

// CheckRun publishes deployment status (only when checks:write granted).
type CheckRun struct {
	Name       string `json:"name"`
	HeadSHA    string `json:"head_sha"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion,omitempty"`
	DetailsURL string `json:"details_url,omitempty"`
	ExternalID string `json:"external_id,omitempty"`
	Output     *struct {
		Title   string `json:"title"`
		Summary string `json:"summary"`
	} `json:"output,omitempty"`
}

// CreateCheckRun creates a check run.
func (a *App) CreateCheckRun(ctx context.Context, installationID, repoID int64, repoFullName string, cr CheckRun) error {
	t, err := a.InstallationToken(ctx, installationID, []int64{repoID}, map[string]string{"checks": "write"})
	if err != nil {
		return err
	}
	_, err = a.do(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/check-runs", repoFullName), "token "+t.Token, cr, nil)
	return err
}

// ManifestConversion is the result of the App Manifest flow.
type ManifestConversion struct {
	ID            int64  `json:"id"`
	Slug          string `json:"slug"`
	Name          string `json:"name"`
	ClientID      string `json:"client_id"`
	ClientSecret  string `json:"client_secret"`
	WebhookSecret string `json:"webhook_secret"`
	PEM           string `json:"pem"`
	HTMLURL       string `json:"html_url"`
}

// ConvertManifest exchanges a manifest code for app credentials.
func ConvertManifest(ctx context.Context, apiURL, code string) (*ManifestConversion, error) {
	a := NewApp(0, nil, apiURL)
	var out ManifestConversion
	_, err := a.do(ctx, http.MethodPost, "/app-manifests/"+url.PathEscape(code)+"/conversions", "", map[string]any{}, &out)
	return &out, err
}

// Manifest builds the GitHub App manifest requesting minimum permissions
// (PRD §6.1). Pull-request read is requested so previews can be enabled per
// project; checks write is optional and off by default.
func Manifest(name, publicURL string, withChecks bool) map[string]any {
	perms := map[string]string{"contents": "read", "metadata": "read", "pull_requests": "read"}
	if withChecks {
		perms["checks"] = "write"
	}
	return map[string]any{
		"name":                name,
		"url":                 publicURL,
		"hook_attributes":     map[string]any{"url": strings.TrimRight(publicURL, "/") + "/webhooks/github", "active": true},
		"redirect_url":        strings.TrimRight(publicURL, "/") + "/settings/git/callback",
		"setup_url":           strings.TrimRight(publicURL, "/") + "/new",
		"public":              false,
		"default_permissions": perms,
		"default_events":      []string{"push", "pull_request"},
	}
}
