package runtime

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/audit"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/ids"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/ipc"
)

const reg = "127.0.0.1:5010"

func goodSpec() Spec {
	env := ids.New("env")
	return Spec{ID: ids.New("wkl"), ProjectID: ids.New("prj"), EnvironmentID: env, DeploymentID: ids.New("dep"), Service: "web", Kind: "app",
		Image: reg + "/od/prj-x@sha256:" + strings.Repeat("a", 64), Runtime: RuntimeRunc, Port: 8080, MemoryBytes: 256 << 20, CPU: 1, PIDs: 256,
		ReadOnlyRoot: true, Network: env}
}

func TestValidateAccepts(t *testing.T) {
	s := goodSpec()
	if err := s.Validate(reg, map[string]bool{"runc": true}); err != nil {
		t.Fatal(err)
	}
}

// ST-04 / Q32 / Q63 / Q64: spec validation rejects escapes.
func TestValidateRejects(t *testing.T) {
	cases := map[string]func(s *Spec){
		"foreign image":      func(s *Spec) { s.Image = "docker.io/library/alpine:latest" },
		"tag not digest":     func(s *Spec) { s.Image = reg + "/od/x:latest" },
		"no memory":          func(s *Spec) { s.MemoryBytes = 0 },
		"no pids":            func(s *Spec) { s.PIDs = 0 },
		"proc tmpfs":         func(s *Spec) { s.Tmpfs = []string{"/proc/sys"} },
		"socket mount":       func(s *Spec) { s.Volumes = []VolumeMount{{VolumeID: ids.New("vol"), Target: "/var/run/docker.sock"}} },
		"host path volume":   func(s *Spec) { s.Volumes = []VolumeMount{{VolumeID: "../../etc", Target: "/data"}} },
		"root target":        func(s *Spec) { s.Volumes = []VolumeMount{{VolumeID: ids.New("vol"), Target: "/"}} },
		"ld_preload":         func(s *Spec) { s.Env = map[string]string{"LD_PRELOAD": "/x.so"} },
		"runsc unavailable":  func(s *Spec) { s.Runtime = RuntimeRunsc },
		"unknown capability": func(s *Spec) { s.Capabilities = []string{"privileged"} },
		"bad user":           func(s *Spec) { s.User = "root" },
		"bad backing image":  func(s *Spec) { s.Kind = "backing"; s.Image = "evil/postgres" },
		"secret path":        func(s *Spec) { s.SecretFiles = map[string]string{"../x": "v"} },
	}
	for name, mut := range cases {
		s := goodSpec()
		mut(&s)
		if err := s.Validate(reg, map[string]bool{"runc": true}); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestServiceAuditsAndDeniesMissingDevice(t *testing.T) {
	f := NewFake()
	mem := &audit.Memory{}
	svc := &Service{Backend: f, Registry: reg, Audit: mem}
	s := goodSpec()
	_, _ = f.EnsureNetwork(context.Background(), NetworkSpec{EnvironmentID: s.EnvironmentID, ProjectID: s.ProjectID})
	if _, err := svc.Start(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	s2 := goodSpec()
	s2.Capabilities = []string{"gpu"}
	if _, err := svc.Start(context.Background(), s2); !ipc.IsCode(err, ipc.CodeForbidden) {
		t.Fatalf("got %v", err)
	}
	ev := mem.Find("workload.start")
	if len(ev) != 2 || ev[0].Result != audit.Success || ev[1].Result != audit.Denied {
		t.Fatalf("%+v", ev)
	}
}

// TestDockerIntegration starts a real hardened container when
// OPENDEPLOY_DOCKER_TESTS=1 and verifies the isolation settings.
func TestDockerIntegration(t *testing.T) {
	if os.Getenv("OPENDEPLOY_DOCKER_TESTS") != "1" {
		t.Skip("set OPENDEPLOY_DOCKER_TESTS=1 to run")
	}
	d, err := NewDocker("unix:///var/run/docker.sock", t.TempDir(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	s := goodSpec()
	s.Kind = "backing"
	s.Image = TemplateImages["redis"]
	s.Port = 6379
	s.SecretFiles = map[string]string{"api_key": "s3cret-value"}
	if _, err := d.EnsureNetwork(ctx, NetworkSpec{EnvironmentID: s.EnvironmentID, ProjectID: s.ProjectID, Kind: "production"}); err != nil {
		t.Fatal(err)
	}
	defer d.RemoveNetwork(ctx, s.EnvironmentID)
	w, err := d.Start(ctx, &s, RegistryAuth{})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Remove(ctx, s.ID)
	if w.State != "running" || w.Endpoint == "" {
		t.Fatalf("%+v", w)
	}
	var in struct {
		HostConfig struct {
			Privileged     bool
			CapDrop        []string
			ReadonlyRootfs bool
			SecurityOpt    []string
			PortBindings   map[string]any
			PidsLimit      int64
			Memory         int64
		}
	}
	if err := d.call(ctx, http.MethodGet, "/containers/"+containerName(s.ID)+"/json", nil, nil, nil, &in); err != nil {
		t.Fatal(err)
	}
	h := in.HostConfig
	if h.Privileged || len(h.CapDrop) == 0 || h.CapDrop[0] != "ALL" || !h.ReadonlyRootfs || len(h.PortBindings) != 0 || h.PidsLimit != 256 || h.Memory != 256<<20 {
		t.Fatalf("hardening missing: %+v", h)
	}
	time.Sleep(time.Second)
	if _, err := d.Logs(ctx, s.ID, 10, time.Time{}); err != nil {
		t.Fatal(err)
	}
	list, _ := d.List(ctx, map[string]string{"environment": s.EnvironmentID})
	if len(list) != 1 {
		t.Fatalf("list %d", len(list))
	}
}
