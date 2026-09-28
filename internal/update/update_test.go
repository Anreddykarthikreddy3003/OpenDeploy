package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func releaseTarball(t *testing.T, files map[string]string, extra func(tw *tar.Writer)) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for name, body := range files {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte(body))
	}
	if extra != nil {
		extra(tw)
	}
	_ = tw.Close()
	_ = zw.Close()
	return buf.Bytes()
}

type repoFixture struct {
	pub   *Publisher
	srv   *httptest.Server
	root1 []byte
	keys  map[string][]ed25519.PrivateKey
}

func newRepo(t *testing.T) *repoFixture {
	t.Helper()
	keys := map[string][]ed25519.PrivateKey{}
	for role, n := range map[string]int{"root": 3, "targets": 1, "snapshot": 1, "timestamp": 1} {
		for i := 0; i < n; i++ {
			_, k, _ := ed25519.GenerateKey(nil)
			keys[role] = append(keys[role], k)
		}
	}
	dir := t.TempDir()
	pub, err := InitRepository(dir, keys, 2)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.FileServer(http.Dir(dir)))
	t.Cleanup(srv.Close)
	root1, err := os.ReadFile(filepath.Join(dir, "metadata", "1.root.json"))
	if err != nil {
		t.Fatal(err)
	}
	return &repoFixture{pub: pub, srv: srv, root1: root1, keys: keys}
}

func (r *repoFixture) client(t *testing.T) *Client {
	return &Client{MetadataURL: r.srv.URL + "/metadata", TargetsURL: r.srv.URL + "/targets", TrustedRoot: r.root1, CacheDir: t.TempDir()}
}

var goodFiles = map[string]string{"bin/platformd": "#!platformd v2.1.0", "bin/opendeployctl": "#!ctl"}

func TestUpdateHappyPathAndInstall(t *testing.T) {
	r := newRepo(t)
	if err := r.pub.PublishRelease(Release{Version: "2.1.0", Channel: "stable", SchemaVersion: 1}, map[string][]byte{"linux-amd64": releaseTarball(t, goodFiles, nil)}); err != nil {
		t.Fatal(err)
	}
	c := r.client(t)
	rel, err := c.Check("stable")
	if err != nil {
		t.Fatal(err)
	}
	if rel.Version != "2.1.0" || Permit("2.0.3", rel) != nil {
		t.Fatalf("release %+v", rel)
	}
	p, err := c.Fetch(rel, "linux-amd64", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Fetch(rel, "windows-arm64", t.TempDir()); !errors.Is(err, ErrNoBuild) {
		t.Fatalf("missing platform: %v", err)
	}
	slots := &Slots{Dir: t.TempDir()}
	_ = os.MkdirAll(filepath.Join(slots.Dir, "a", "bin"), 0o755)
	if err := slots.Activate("a"); err != nil {
		t.Fatal(err)
	}
	slot, err := slots.Stage(rel.Version, rel.SchemaVersion, p)
	if err != nil || slot != "b" {
		t.Fatalf("stage %s %v", slot, err)
	}
	restarts := 0
	err = slots.Apply(context.Background(), Hooks{Restart: func(context.Context) error { restarts++; return nil }, Healthy: func(context.Context) error { return nil }}, 2*time.Second)
	if err != nil || restarts != 1 {
		t.Fatalf("apply %v restarts %d", err, restarts)
	}
	if tgt, _ := os.Readlink(filepath.Join(slots.Dir, "current")); tgt != "b" {
		t.Fatalf("current -> %s", tgt)
	}
	b, _ := os.ReadFile(filepath.Join(slots.Dir, "current", "bin", "platformd"))
	if string(b) != goodFiles["bin/platformd"] {
		t.Fatalf("installed %q", b)
	}
}

// ST-10 / Q42-Q46, Q78-Q79.
func TestUpdateSupplyChainAttacks(t *testing.T) {
	r := newRepo(t)
	art := releaseTarball(t, goodFiles, nil)
	if err := r.pub.PublishRelease(Release{Version: "2.1.0", Channel: "stable"}, map[string][]byte{"linux-amd64": art}); err != nil {
		t.Fatal(err)
	}
	c := r.client(t)
	rel, err := c.Check("stable")
	if err != nil {
		t.Fatal(err)
	}
	dir := r.pub.Dir

	t.Run("tampered artifact", func(t *testing.T) {
		p := filepath.Join(dir, "targets", filepath.FromSlash(rel.Artifacts["linux-amd64"]))
		orig, _ := os.ReadFile(p)
		evil := releaseTarball(t, map[string]string{"bin/platformd": "#!backdoor", "bin/opendeployctl": "x"}, nil)
		_ = os.WriteFile(p, evil, 0o644)
		defer os.WriteFile(p, orig, 0o644)
		_, err := c.Fetch(rel, "linux-amd64", t.TempDir())
		if err == nil {
			t.Fatal("tampered artifact accepted")
		}
		t.Logf("rejected: %v", err)
	})

	t.Run("tampered channel document", func(t *testing.T) {
		p := filepath.Join(dir, "targets", "channels", "stable.json")
		orig, _ := os.ReadFile(p)
		_ = os.WriteFile(p, bytes.Replace(orig, []byte(`"2.1.0"`), []byte(`"9.9.9"`), 1), 0o644)
		defer os.WriteFile(p, orig, 0o644)
		_, err := r.client(t).Check("stable")
		if err == nil {
			t.Fatal("tampered release document accepted")
		}
		t.Logf("rejected: %v", err)
	})

	t.Run("expired metadata (freeze attack)", func(t *testing.T) {
		fc := r.client(t)
		fc.RefTime = time.Now().Add(TimestampExpiry + time.Hour)
		if _, err := fc.Check("stable"); err == nil || !strings.Contains(strings.ToLower(err.Error()), "expire") {
			t.Fatalf("expired timestamp accepted: %v", err)
		}
	})

	t.Run("rollback to older metadata", func(t *testing.T) {
		rc := r.client(t)
		if _, err := rc.Check("stable"); err != nil {
			t.Fatal(err)
		}
		old := map[string][]byte{}
		for _, n := range []string{"timestamp.json", "snapshot.json", "targets.json"} {
			old[n], _ = os.ReadFile(filepath.Join(dir, "metadata", n))
		}
		// Publisher moves on; the client sees the newer versions.
		if err := r.pub.PublishRelease(Release{Version: "2.1.1", Channel: "stable"}, map[string][]byte{"linux-amd64": art}); err != nil {
			t.Fatal(err)
		}
		if rel, err := rc.Check("stable"); err != nil || rel.Version != "2.1.1" {
			t.Fatalf("newer release: %v %v", rel, err)
		}
		// An attacker (or stale mirror) serves the old, validly signed set.
		for n, b := range old {
			_ = os.WriteFile(filepath.Join(dir, "metadata", n), b, 0o644)
		}
		_, err := rc.Check("stable")
		if err == nil {
			t.Fatal("metadata rollback accepted")
		}
		t.Logf("rejected: %v", err)
		// Restore the current repository for later subtests.
		if err := r.pub.BumpTimestamp(); err != nil {
			t.Fatal(err)
		}
		_ = r.pub.write("targets")
		_ = r.pub.write("snapshot")
	})

	t.Run("root rotation signed by a single key", func(t *testing.T) {
		evil, _ := LoadPublisher(dir, r.keys)
		evil.Root.Signed.Version++
		_, attacker, _ := ed25519.GenerateKey(nil)
		ak, _ := metadata.KeyFromPublicKey(attacker.Public())
		_ = evil.Root.Signed.AddKey(ak, "targets")
		evil.Keys = map[string][]ed25519.PrivateKey{"root": r.keys["root"][:1]}
		if err := evil.signWrite("root"); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(filepath.Join(dir, "metadata", "2.root.json"))
		_, err := r.client(t).Check("stable")
		if err == nil {
			t.Fatal("root signed below threshold accepted")
		}
		t.Logf("rejected: %v", err)
	})

	t.Run("targets signed by an unauthorized key", func(t *testing.T) {
		evil, _ := LoadPublisher(dir, r.keys)
		_, attacker, _ := ed25519.GenerateKey(nil)
		evil.Keys = map[string][]ed25519.PrivateKey{"targets": {attacker}, "snapshot": r.keys["snapshot"], "timestamp": r.keys["timestamp"]}
		if err := evil.AddTarget(ChannelTarget("stable"), []byte(`{"version":"6.6.6","channel":"stable","artifacts":{}}`)); err != nil {
			t.Fatal(err)
		}
		if err := evil.Commit(); err != nil {
			t.Fatal(err)
		}
		rel, err := r.client(t).Check("stable")
		if err == nil {
			t.Fatalf("unauthorised targets accepted: %+v", rel)
		}
		t.Logf("rejected: %v", err)
	})
}

func TestReleasePolicy(t *testing.T) {
	rel := &Release{Version: "2.1.0"}
	if err := Permit("2.2.0", rel); !errors.Is(err, ErrDowngrade) {
		t.Fatalf("downgrade: %v", err)
	}
	if err := Permit("2.1.0-rc.1", rel); err != nil {
		t.Fatalf("rc -> release: %v", err)
	}
	if err := Permit("dev", rel); err != nil {
		t.Fatalf("dev build: %v", err)
	}
	if err := Permit("2.0.0", &Release{Version: "2.1.0", Halted: true}); !errors.Is(err, ErrHalted) {
		t.Fatalf("halt: %v", err)
	}
	if err := Permit("2.0.0", &Release{Version: "2.1.0", Revoked: []string{"2.1.0"}}); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked: %v", err)
	}
	if !CurrentRevoked("v2.0.1", &Release{Version: "2.1.0", Revoked: []string{"2.0.1"}}) {
		t.Fatal("revoked current not detected")
	}
	if _, err := ParseVersion("2.1"); err == nil {
		t.Fatal("bad version parsed")
	}
}

func TestSlotsRollbackAndMigrationSafety(t *testing.T) {
	ctx := context.Background()
	mk := func(t *testing.T, schemaOld, schemaNew int) (*Slots, string) {
		s := &Slots{Dir: t.TempDir()}
		_ = os.MkdirAll(filepath.Join(s.Dir, "a", "bin"), 0o755)
		_ = s.Activate("a")
		st, _ := s.State()
		st.Versions["a"], st.Schemas["a"] = "2.0.0", schemaOld
		_ = s.save(st)
		tb := filepath.Join(t.TempDir(), "r.tar.gz")
		_ = os.WriteFile(tb, releaseTarball(t, goodFiles, nil), 0o644)
		if _, err := s.Stage("2.1.0", schemaNew, tb); err != nil {
			t.Fatal(err)
		}
		return s, tb
	}
	unhealthy := func(context.Context) error { return errors.New("readiness failed") }
	restart := func(context.Context) error { return nil }

	s, _ := mk(t, 1, 1)
	if err := s.Apply(ctx, Hooks{Restart: restart, Healthy: unhealthy}, time.Second); !errors.Is(err, ErrRolledBack) {
		t.Fatalf("expected rollback: %v", err)
	}
	if tgt, _ := os.Readlink(filepath.Join(s.Dir, "current")); tgt != "a" {
		t.Fatalf("not rolled back: current -> %s", tgt)
	}

	s, _ = mk(t, 1, 2)
	backups := 0
	err := s.Apply(ctx, Hooks{Restart: restart, Healthy: unhealthy, Backup: func(context.Context) error { backups++; return nil }}, time.Second)
	if !errors.Is(err, ErrManualAction) || backups != 1 {
		t.Fatalf("migration case: %v backups=%d", err, backups)
	}
	s, _ = mk(t, 1, 2)
	if err := s.Apply(ctx, Hooks{Restart: restart, Healthy: unhealthy, Backup: func(context.Context) error { return errors.New("s3 down") }}, time.Second); err == nil ||
		!strings.Contains(err.Error(), "backup failed") {
		t.Fatalf("update must abort without a pre-migration backup: %v", err)
	}
	if tgt, _ := os.Readlink(filepath.Join(s.Dir, "current")); tgt != "a" {
		t.Fatal("aborted update switched slots")
	}

	// Malicious archives never stage.
	for name, tb := range map[string][]byte{
		"symlink": releaseTarball(t, goodFiles, func(tw *tar.Writer) {
			_ = tw.WriteHeader(&tar.Header{Name: "bin/evil", Typeflag: tar.TypeSymlink, Linkname: "/etc/shadow"})
		}),
		"traversal":  releaseTarball(t, map[string]string{"../../etc/cron.d/x": "pwn", "bin/platformd": "x", "bin/opendeployctl": "y"}, nil),
		"incomplete": releaseTarball(t, map[string]string{"bin/platformd": "x"}, nil),
	} {
		s := &Slots{Dir: t.TempDir()}
		p := filepath.Join(t.TempDir(), "r.tar.gz")
		_ = os.WriteFile(p, tb, 0o644)
		if _, err := s.Stage("9.9.9", 1, p); err == nil {
			t.Fatalf("%s archive staged", name)
		}
	}
}
