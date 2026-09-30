package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestPubliclyReachable(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		// Not reachable from GitHub.
		{"http://127.0.0.1:8080", false},
		{"http://127.0.0.1:8080/", false},
		{"http://127.1.2.3", false},
		{"http://[::1]:8080", false},
		{"http://[::ffff:127.0.0.1]:8080", false},
		{"http://10.0.0.5", false},
		{"http://172.16.0.1", false},
		{"http://172.31.255.254", false},
		{"http://192.168.1.10:8080", false},
		{"http://[fd12:3456::1]", false},
		{"http://[fc00::1]", false},
		{"http://169.254.1.1", false},
		{"http://[fe80::1]", false},
		{"http://0.0.0.0:8080", false},
		{"http://[::]:8080", false},
		{"http://100.64.0.1", false},
		{"http://100.127.255.254", false},
		{"http://224.0.0.1", false},
		{"http://localhost:8080", false},
		{"http://LOCALHOST", false},
		{"http://localhost.:8080", false},
		{"http://dash.localhost", false},
		{"http://mybox.local", false},
		{"http://node.corp.internal", false},
		{"http://myhost:8080", false},
		{"", false},
		{"not a url", false},
		{"http://", false},
		{"ftp://example.com", false},
		{"//example.com", false},
		// Reachable: public addresses and multi-label public names.
		{"https://deploy.example.com", true},
		{"https://deploy.example.com/", true},
		{"http://deploy.example.com:8080", true},
		{"https://tenant.relay.example.net", true},
		{"http://140.82.112.3", true},
		{"http://100.63.255.255", true},
		{"http://100.128.0.1", true},
		{"http://172.32.0.1", true},
		{"http://[2606:4700::1111]", true},
		{"https://example.localhost.com", true},
	}
	for _, c := range cases {
		if got := PubliclyReachable(c.url); got != c.want {
			t.Errorf("PubliclyReachable(%q) = %v, want %v", c.url, got, c.want)
		}
	}
}

// F-8: GitHub rejects a manifest whose hook URL is not on the public
// Internet, so a node it cannot reach must not send one.
func TestManifestWithoutWebhookWhenUnreachable(t *testing.T) {
	for _, u := range []string{"http://127.0.0.1:8080", "http://localhost:8080/", "http://192.168.1.10:8080", "http://mybox.local"} {
		for _, checks := range []bool{false, true} {
			m := Manifest("OpenDeploy", u, checks)
			if _, ok := m["hook_attributes"]; ok {
				t.Errorf("%s checks=%v: manifest has hook_attributes: %v", u, checks, m["hook_attributes"])
			}
			if _, ok := m["default_events"]; ok {
				t.Errorf("%s checks=%v: manifest has default_events: %v", u, checks, m["default_events"])
			}
			base := trimSlash(u)
			want := map[string]any{"name": "OpenDeploy", "url": u, "redirect_url": base + "/settings/git/callback",
				"setup_url": base + "/new", "public": false, "default_permissions": wantPerms(checks)}
			if !reflect.DeepEqual(m, want) {
				t.Errorf("%s checks=%v:\n got %v\nwant %v", u, checks, m, want)
			}
		}
	}
}

// A node GitHub can reach keeps the manifest it always had.
func TestManifestWithWebhookWhenReachable(t *testing.T) {
	for _, u := range []string{"https://deploy.example.com", "https://deploy.example.com/", "https://tenant.relay.example.net"} {
		for _, checks := range []bool{false, true} {
			base := trimSlash(u)
			want := map[string]any{
				"name":                "OpenDeploy",
				"url":                 u,
				"hook_attributes":     map[string]any{"url": base + "/webhooks/github", "active": true},
				"redirect_url":        base + "/settings/git/callback",
				"setup_url":           base + "/new",
				"public":              false,
				"default_permissions": wantPerms(checks),
				"default_events":      []string{"push", "pull_request"},
			}
			if got := Manifest("OpenDeploy", u, checks); !reflect.DeepEqual(got, want) {
				t.Errorf("%s checks=%v:\n got %v\nwant %v", u, checks, got, want)
			}
		}
	}
}

func wantPerms(checks bool) map[string]string {
	p := map[string]string{"contents": "read", "metadata": "read", "pull_requests": "read"}
	if checks {
		p["checks"] = "write"
	}
	return p
}

func trimSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

// GitHub returns "webhook_secret": null for an App without a webhook; the
// conversion must succeed with an empty secret.
func TestConvertManifestNullWebhookSecret(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/app-manifests/abc/conversions" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": 42, "slug": "opendeploy-x", "name": "OpenDeploy x",
			"client_id": "Iv1.x", "client_secret": "cs", "webhook_secret": nil, "pem": "-----BEGIN RSA PRIVATE KEY-----"})
	}))
	defer srv.Close()
	conv, err := ConvertManifest(context.Background(), srv.URL, "abc")
	if err != nil {
		t.Fatal(err)
	}
	if conv.ID != 42 || conv.Slug != "opendeploy-x" || conv.WebhookSecret != "" {
		t.Fatalf("%+v", conv)
	}
}
