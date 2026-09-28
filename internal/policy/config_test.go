package policy

import (
	"strings"
	"testing"
	"time"
)

const prdExample = `version: 2
project: example-api
source:
  production_branch: main
  trust: trusted
build:
  strategy: auto
  root: .
  network_policy: dependency
  timeout: 20m
runtime:
  type: web
  port: 8080
  sandbox: auto
  read_only_root: true
  capabilities: []
health:
  startup:
    path: /health/startup
    grace: 45s
  readiness:
    path: /health/ready
  smoke:
    - name: homepage
      request: GET /
      expect_status: 200
resources:
  memory: 512Mi
  cpu: 1.0
  pids: 256
egress:
  internet: true
  allow_private_networks: false
  allow_hosts: []
release:
  zero_downtime: true
  keep_deployments: 5
  auto_promote: true
previews:
  enabled: true
  public_forks: false
  secrets_scope: preview
  database: ephemeral
  max_active: 3
volumes:
  - name: uploads
    mount: /app/uploads
    backup: daily
`

func TestParsePRDExample(t *testing.T) {
	c, err := Parse([]byte(prdExample))
	if err != nil {
		t.Fatal(err)
	}
	if c.Project != "example-api" || c.Runtime.Port != 8080 || c.Build.Timeout.Duration != 20*time.Minute {
		t.Fatalf("unexpected parse: %+v", c)
	}
	if c.Health.Startup.Grace.Duration != 45*time.Second {
		t.Fatalf("grace = %v", c.Health.Startup.Grace)
	}
	if len(c.Volumes) != 1 || c.Volumes[0].Mount != "/app/uploads" {
		t.Fatalf("volumes = %+v", c.Volumes)
	}
}

func TestEmptyConfigGetsSecureDefaults(t *testing.T) {
	c, err := Parse(nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Source.Trust != TrustTrusted || !*c.Runtime.ReadOnlyRoot || c.Egress.AllowPrivateNetworks {
		t.Fatalf("defaults not secure: %+v", c)
	}
	if c.Previews.PublicForks {
		t.Fatal("public forks must default off")
	}
}

func TestRejects(t *testing.T) {
	cases := map[string]string{
		"unknown field":          "version: 2\nbogus: 1\n",
		"escape root":            "build:\n  root: ../../etc\n",
		"abs root":               "build:\n  root: /etc\n",
		"unknown capability":     "runtime:\n  capabilities: [\"privileged\"]\n",
		"prod secret inherit":    "previews:\n  secrets_scope: production\n",
		"prod db linkage":        "previews:\n  database: production\n",
		"proc mount":             "volumes:\n  - name: x\n    mount: /proc/self\n",
		"root mount":             "volumes:\n  - name: x\n    mount: /\n",
		"bad version":            "version: 1\n",
		"bad smoke":              "health:\n  smoke:\n    - name: a\n      request: \"GET http://evil\"\n",
		"bad memory":             "resources:\n  memory: 1TB\n",
		"tiny memory":            "resources:\n  memory: 1Mi\n",
		"bad allow host":         "egress:\n  allow_hosts: [\"http://x\"]\n",
		"bad branch":             "source:\n  production_branch: \"a..b\"\n",
		"bad trust":              "source:\n  trust: root\n",
		"service unknown volume": "services:\n  - name: db\n    template: postgres\n    volume: nope\n",
		"bad service template":   "services:\n  - name: db\n    template: oracle\n",
	}
	for name, y := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(y)); err == nil {
				t.Fatalf("expected rejection for %q", y)
			}
		})
	}
}

func TestOversize(t *testing.T) {
	if _, err := Parse([]byte(strings.Repeat("#", MaxConfigBytes+1))); err == nil {
		t.Fatal("expected size rejection")
	}
}

func TestParseMemory(t *testing.T) {
	for in, want := range map[string]int64{"512Mi": 512 << 20, "1Gi": 1 << 30, "64Ki": 64 << 10} {
		got, err := ParseMemory(in)
		if err != nil || got != want {
			t.Fatalf("%s: got %d %v", in, got, err)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(prdExample))
	f.Add([]byte("version: 2"))
	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := Parse(b)
		if err == nil {
			// Anything accepted must re-validate and never enable prod inheritance.
			if c.Previews.SecretsScope == "production" {
				t.Fatal("accepted production secret scope")
			}
			if err := c.Validate(); err != nil {
				t.Fatal(err)
			}
		}
	})
}
