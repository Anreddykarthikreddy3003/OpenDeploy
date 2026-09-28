package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/allinone"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/backup"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/config"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/restore"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/runtime"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/services"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/store"
)

// ST-11 / Q56-Q57: encrypted backup of a live node and restore onto a clean
// node that comes back with its users, projects, secrets, audit chain,
// artifacts and volumes.
func TestBackupAndCleanNodeRestore(t *testing.T) {
	ctx := context.Background()
	backups := t.TempDir()
	mutate := func(n *config.Node) {
		n.Backup.LocalDir = backups
		n.Backup.Enabled = true
	}
	ip := nonLoopbackIP(t)
	ln, err := net.Listen("tcp", ip+":0")
	if err != nil {
		t.Fatal(err)
	}
	app := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })}
	go app.Serve(ln)
	defer app.Close()
	endpoint := func(*runtime.Spec) string { return ln.Addr().String() }
	dataA := t.TempDir()
	fakeA := runtime.NewFake()
	fakeA.EndpointFor = endpoint
	a, err := allinone.Start(ctx, allinone.Options{DataDir: dataA, Backend: fakeA, Executor: &ociExec{}, Fetch: fixtureFetch, Mutate: mutate})
	if err != nil {
		t.Fatal(err)
	}
	c := newClient(t, "http://"+a.APIAddr)
	tok, _ := os.ReadFile(services.BootstrapTokenPath(a.Node))
	var sess struct {
		CSRFToken string `json:"csrf_token"`
	}
	c.do("POST", "/api/v2/auth/bootstrap", map[string]string{"token": strings.TrimSpace(string(tok)), "email": "o@example.com", "password": "correct horse battery"}, &sess)
	c.csrf = sess.CSRFToken
	var created struct {
		Project    store.Project     `json:"project"`
		Deployment *store.Deployment `json:"deployment"`
	}
	if code := c.do("POST", "/api/v2/projects", map[string]any{"name": "web", "clone_url": "https://140.82.112.3/example/web.git",
		"env": map[string]string{"API_KEY": "s3cr3t-value"}}, &created); code != 201 {
		t.Fatalf("create project %d", code)
	}
	dep := waitStatus(t, c, created.Deployment.ID, "SUCCEEDED")
	// A volume with data.
	env, _ := a.P.Store.GetEnvironmentByName(ctx, created.Project.ID, "production")
	vol, err := a.P.Store.EnsureVolume(ctx, created.Project.ID, env.ID, "data", "/data", "daily")
	if err != nil {
		t.Fatal(err)
	}
	vdir := filepath.Join(a.Node.Runtime.VolumesDir, vol.ID)
	_ = os.MkdirAll(filepath.Join(vdir, "sub"), 0o755)
	_ = os.WriteFile(filepath.Join(vdir, "sub", "row.txt"), []byte("persistent-row"), 0o644)

	// ---- run a backup through the job queue
	if code := c.do("POST", "/api/v2/system/backups", map[string]any{}, nil); code != 202 {
		t.Fatalf("run backup %d", code)
	}
	var st struct {
		Status struct {
			MasterKeyID     string `json:"master_key_id"`
			SignerPublicKey string `json:"signer_public_key"`
			Last            *struct {
				ID    string `json:"id"`
				OK    bool   `json:"ok"`
				Error string `json:"error"`
			} `json:"last"`
		} `json:"status"`
		Backups []struct {
			ID         string             `json:"id"`
			Components []backup.Component `json:"components"`
		} `json:"backups"`
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		c.do("GET", "/api/v2/system/backups", nil, &st)
		if st.Status.Last != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("backup did not run")
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !st.Status.Last.OK || len(st.Backups) != 1 {
		t.Fatalf("backup failed: %+v", st.Status.Last)
	}
	kinds := map[string]bool{}
	for _, comp := range st.Backups[0].Components {
		kinds[comp.Kind] = true
	}
	for _, k := range []string{"platform-db", "audit-db", "secrets", "artifacts", "volume"} {
		if !kinds[k] {
			t.Fatalf("backup lacks %s: %+v", k, st.Backups[0].Components)
		}
	}
	// The master key export is re-auth protected and audited.
	var mk struct {
		MasterKey string `json:"master_key"`
	}
	if code := c.do("POST", "/api/v2/system/backups/master-key", map[string]any{}, &mk); code != 200 || len(mk.MasterKey) != 64 {
		t.Fatalf("master key export %d", code)
	}
	// Nothing sensitive in plaintext at rest.
	_ = filepath.Walk(backups, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			b, _ := os.ReadFile(p)
			for _, needle := range []string{"s3cr3t-value", "persistent-row", "correct horse"} {
				if strings.Contains(string(b), needle) {
					t.Fatalf("plaintext %q found in backup object %s", needle, p)
				}
			}
		}
		return nil
	})
	signer := st.Status.SignerPublicKey
	a.Close()

	// ---- restore onto a clean node
	dataB := t.TempDir()
	nb := &config.Node{DataDir: dataB, RunDir: t.TempDir()}
	nb.ApplyDefaults()
	master, _ := backup.ParseMasterKey(mk.MasterKey)
	pub, _ := base64.StdEncoding.DecodeString(signer)
	tgt := &backup.LocalTarget{Dir: backups}
	var wrong backup.MasterKey
	_, _ = rand.Read(wrong[:])
	if _, err := restore.Run(ctx, restore.Options{Node: nb, Target: tgt, Prefix: nb.Backup.Prefix, Master: wrong, Signer: pub}); err == nil {
		t.Fatal("restore with the wrong master key succeeded")
	}
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := restore.Run(ctx, restore.Options{Node: nb, Target: tgt, Prefix: nb.Backup.Prefix, Master: master, Signer: otherPub}); !errors.Is(err, backup.ErrUntrustedSigner) {
		t.Fatalf("restore with an unexpected signer: %v", err)
	}
	if _, err := restore.Run(ctx, restore.Options{Node: nb, Target: tgt, Prefix: nb.Backup.Prefix, ID: "latest", Master: master, Signer: pub}); err != nil {
		t.Fatal(err)
	}
	if _, err := restore.Run(ctx, restore.Options{Node: nb, Target: tgt, Prefix: nb.Backup.Prefix, Master: master, Signer: pub}); !errors.Is(err, restore.ErrNotClean) {
		t.Fatalf("second restore over live state: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(nb.Runtime.VolumesDir, vol.ID, "sub", "row.txt")); err != nil || string(b) != "persistent-row" {
		t.Fatalf("volume not restored: %q %v", b, err)
	}

	fakeB := runtime.NewFake()
	fakeB.EndpointFor = endpoint
	b, err := allinone.Start(ctx, allinone.Options{DataDir: dataB, Backend: fakeB, Executor: &ociExec{}, Fetch: fixtureFetch, Mutate: mutate})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	cb := newClient(t, "http://"+b.APIAddr)
	cb.login("o@example.com", "correct horse battery")
	var proj struct {
		Project      store.Project `json:"project"`
		Environments []struct {
			CurrentDeploymentID string `json:"current_deployment_id"`
		} `json:"environments"`
	}
	if code := cb.do("GET", "/api/v2/projects/"+created.Project.ID, nil, &proj); code != 200 || proj.Environments[0].CurrentDeploymentID != dep["id"] {
		t.Fatalf("project not restored: %d %+v", code, proj)
	}
	var metas []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	cb.do("GET", "/api/v2/projects/"+created.Project.ID+"/secrets?environment=production", nil, &metas)
	if len(metas) != 1 {
		t.Fatalf("secrets %v", metas)
	}
	var rev struct {
		Value string `json:"value"`
	}
	if code := cb.do("POST", "/api/v2/projects/"+created.Project.ID+"/secrets/"+metas[0].ID+"/reveal", map[string]string{"reason": "restore drill"}, &rev); code != 200 || rev.Value != "s3cr3t-value" {
		t.Fatalf("secret not decryptable after restore: %d %q", code, rev.Value)
	}
	var ver map[string]any
	cb.do("GET", "/api/v2/system/audit/verify", nil, &ver)
	if ver["ok"] != true {
		t.Fatalf("audit chain after restore: %v", ver)
	}
	// The reconciler brings the restored desired state back up.
	deadline = time.Now().Add(45 * time.Second)
	for {
		found := false
		for _, sp := range fakeB.Specs {
			if sp.DeploymentID == dep["id"] && sp.Env["API_KEY"] == "s3cr3t-value" {
				found = true
			}
		}
		if found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("restored workload was not started by the reconciler")
		}
		time.Sleep(250 * time.Millisecond)
	}
}
