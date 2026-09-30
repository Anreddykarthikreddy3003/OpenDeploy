// Package cli implements opendeployctl, the OpenDeploy command-line client
// (PRD §21): it talks to the node's /api/v2 with a role-capped API token,
// plus local admin commands (bootstrap token, doctor) and `dev`.
package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Profile is the stored CLI login.
type Profile struct {
	URL   string `json:"url"`
	Token string `json:"token"`
}

func configPath() string {
	if p := os.Getenv("OPENDEPLOY_CLI_CONFIG"); p != "" {
		return p
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = filepath.Join(os.Getenv("HOME"), ".config")
	}
	return filepath.Join(dir, "opendeploy", "cli.json")
}

// LoadProfile reads the profile; environment variables take precedence.
func LoadProfile() (*Profile, error) {
	p := &Profile{}
	if b, err := os.ReadFile(configPath()); err == nil {
		_ = json.Unmarshal(b, p)
	}
	if v := os.Getenv("OPENDEPLOY_URL"); v != "" {
		p.URL = v
	}
	if v := os.Getenv("OPENDEPLOY_TOKEN"); v != "" {
		p.Token = v
	}
	if p.URL == "" {
		p.URL = "http://127.0.0.1:8080"
	}
	return p, nil
}

// Save writes the profile with 0600 permissions.
func (p *Profile) Save() error {
	path := configPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(p, "", "  ")
	return os.WriteFile(path, b, 0o600)
}

// Client is a bearer-token API client.
type Client struct {
	Base  string
	Token string
	HC    *http.Client
}

// NewClient builds a client from the stored profile.
func NewClient() (*Client, error) {
	p, err := LoadProfile()
	if err != nil {
		return nil, err
	}
	if p.Token == "" {
		return nil, errors.New("not logged in: run `opendeployctl login --url URL --token odt_...` (create a token under Account → API tokens)")
	}
	return &Client{Base: strings.TrimSuffix(p.URL, "/"), Token: p.Token, HC: &http.Client{Timeout: 5 * time.Minute}}, nil
}

// APIError is a structured API failure.
type APIError struct {
	Status  int
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *APIError) Error() string {
	switch {
	case e.Code == "session_required":
		return e.Message + " (use the dashboard for this action)"
	case e.Status == 403:
		return e.Message + " (403: your role — or this token's role cap — does not allow it)"
	}
	return fmt.Sprintf("%s (%d %s)", e.Message, e.Status, e.Code)
}

func (c *Client) req(ctx context.Context, method, path string, body io.Reader, ctype string) (*http.Response, error) {
	r, err := http.NewRequestWithContext(ctx, method, c.Base+path, body)
	if err != nil {
		return nil, err
	}
	r.Header.Set("Authorization", "Bearer "+c.Token)
	r.Header.Set("Accept", "application/json")
	if ctype != "" {
		r.Header.Set("Content-Type", ctype)
	}
	res, err := c.HC.Do(r)
	if err != nil {
		return nil, err
	}
	if res.StatusCode >= 400 {
		defer res.Body.Close()
		e := &APIError{Status: res.StatusCode}
		b, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))
		if json.Unmarshal(b, e) != nil || e.Message == "" {
			e.Message = strings.TrimSpace(string(b))
		}
		return nil, e
	}
	return res, nil
}

// Do performs a JSON request and decodes the response into out.
func (c *Client) Do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	ctype := ""
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body, ctype = bytes.NewReader(b), "application/json"
	}
	res, err := c.req(ctx, method, path, body, ctype)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if out == nil {
		_, _ = io.Copy(io.Discard, res.Body)
		return nil
	}
	return json.NewDecoder(res.Body).Decode(out)
}

// Upload posts a raw body.
func (c *Client) Upload(ctx context.Context, path string, body io.Reader, out any) error {
	res, err := c.req(ctx, http.MethodPost, path, body, "application/gzip")
	if err != nil {
		return err
	}
	defer res.Body.Close()
	return json.NewDecoder(res.Body).Decode(out)
}

// SSE streams server-sent events until the stream ends or fn returns false.
func (c *Client) SSE(ctx context.Context, path string, fn func(event string, data []byte) bool) error {
	cl := *c.HC
	cl.Timeout = 0
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Base+path, nil)
	if err != nil {
		return err
	}
	r.Header.Set("Authorization", "Bearer "+c.Token)
	r.Header.Set("Accept", "text/event-stream")
	res, err := cl.Do(r)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 400 {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return fmt.Errorf("stream: %s %s", res.Status, strings.TrimSpace(string(b)))
	}
	sc := bufio.NewScanner(res.Body)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	event := ""
	var data []byte
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			if event != "" || len(data) > 0 {
				if !fn(event, data) {
					return nil
				}
			}
			event, data = "", nil
		case strings.HasPrefix(line, "event:"):
			event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			data = append(data, strings.TrimSpace(strings.TrimPrefix(line, "data:"))...)
		}
	}
	return sc.Err()
}
