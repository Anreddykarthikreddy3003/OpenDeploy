package audit

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/identity"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/ipc"
	_ "modernc.org/sqlite"
)

func newStore(t *testing.T) (*Store, string) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	p := filepath.Join(t.TempDir(), "audit.db")
	s, err := OpenStore(context.Background(), p, priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, p
}

func ev(action string) Event {
	return Event{ActorType: ActorUser, ActorID: "usr_1", Action: action, Result: Success, Details: map[string]string{"reason": "test"}}
}

func TestAppendChainVerify(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	for i := 0; i < 50; i++ {
		if _, err := s.Append(ctx, identity.Platform, ev("deployment.create")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Checkpoint(ctx); err != nil {
		t.Fatal(err)
	}
	r, err := s.Verify(ctx)
	if err != nil || !r.OK || r.Count != 50 || r.CheckpointsVerified != 1 {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestConcurrentAppendsStayChained(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = s.Append(ctx, identity.Secret, ev("secret.set"))
		}()
	}
	wg.Wait()
	r, _ := s.Verify(ctx)
	if !r.OK || r.Count != 20 {
		t.Fatalf("%+v", r)
	}
}

func TestAppendOnlyTriggers(t *testing.T) {
	s, p := newStore(t)
	ctx := context.Background()
	_, _ = s.Append(ctx, identity.Platform, ev("auth.login"))
	db, _ := sql.Open("sqlite", p)
	defer db.Close()
	if _, err := db.Exec(`UPDATE audit_events SET result='denied'`); err == nil {
		t.Fatal("update must be blocked")
	}
	if _, err := db.Exec(`DELETE FROM audit_events`); err == nil {
		t.Fatal("delete must be blocked")
	}
}

// File-level tampering (triggers dropped by an attacker with DB access) is
// detected on next open and puts auditd into degraded mode.
func TestTamperDetected(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	p := filepath.Join(t.TempDir(), "audit.db")
	ctx := context.Background()
	s, _ := OpenStore(ctx, p, priv, nil)
	for i := 0; i < 5; i++ {
		_, _ = s.Append(ctx, identity.Platform, ev("secret.reveal"))
	}
	s.Close()
	db, _ := sql.Open("sqlite", p)
	for _, q := range []string{`DROP TRIGGER audit_no_update`, `UPDATE audit_events SET actor_id='someone_else' WHERE seq=3`} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	s2, err := OpenStore(ctx, p, priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if s2.Degraded() == "" {
		t.Fatal("tampering must degrade")
	}
	r, _ := s2.Verify(ctx)
	if r.OK || r.BrokenAt != 3 {
		t.Fatalf("%+v", r)
	}
}

func TestTruncationDetectedByCheckpoint(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	p := filepath.Join(t.TempDir(), "audit.db")
	ctx := context.Background()
	s, _ := OpenStore(ctx, p, priv, nil)
	for i := 0; i < 5; i++ {
		_, _ = s.Append(ctx, identity.Platform, ev("auth.login"))
	}
	_, _ = s.Checkpoint(ctx)
	s.Close()
	db, _ := sql.Open("sqlite", p)
	_, _ = db.Exec(`DROP TRIGGER audit_no_delete`)
	if _, err := db.Exec(`DELETE FROM audit_events WHERE seq>=4`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	s2, _ := OpenStore(ctx, p, priv, nil)
	defer s2.Close()
	if s2.Degraded() == "" {
		t.Fatal("truncation after checkpoint must be detected")
	}
}

func TestValidateRejects(t *testing.T) {
	bad := []Event{
		{ActorType: ActorUser, Action: "x", Result: Success},
		{ActorType: ActorUser, Action: "a.b", Result: "maybe"},
		{ActorType: "root", Action: "a.b", Result: Success},
		{ActorType: ActorUser, Action: "a.b", Result: Success, Details: map[string]string{"shell": "rm"}},
	}
	for _, e := range bad {
		if e.Validate() == nil {
			t.Errorf("accepted %+v", e)
		}
	}
}

// Q55/ST-06: only control-plane identities may append, and the recorded
// service is the verified caller, not something the caller claims.
func TestIPCIdentityEnforced(t *testing.T) {
	s, _ := newStore(t)
	sock := filepath.Join(t.TempDir(), "audit.sock")
	uid := uint32(os.Getuid())
	ids := ipc.NewIdentityMap(map[uint32]string{uid: identity.Builder})
	srv := ipc.NewServer("auditd", ids, nil)
	Register(srv, s)
	if err := srv.Listen(sock, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)
	time.Sleep(20 * time.Millisecond)
	c := &Client{C: ipc.NewClient(sock)}
	e := ev("build.start")
	e.Service = identity.Platform // attempted spoof
	got, err := c.Append(ctx, e)
	if err != nil {
		t.Fatal(err)
	}
	if got.Service != identity.Builder {
		t.Fatalf("service = %s", got.Service)
	}
	// builderd may not read the audit log.
	if _, err := c.Query(ctx, Query{}); !ipc.IsCode(err, ipc.CodeForbidden) {
		t.Fatalf("query should be forbidden: %v", err)
	}
}

func TestForwarding(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	var mu sync.Mutex
	var got []Event
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(401)
			return
		}
		sc := bufio.NewScanner(r.Body)
		for sc.Scan() {
			var e Event
			_ = json.Unmarshal(sc.Bytes(), &e)
			mu.Lock()
			got = append(got, e)
			mu.Unlock()
		}
	}))
	defer srv.Close()
	for i := 0; i < 7; i++ {
		_, _ = s.Append(ctx, identity.Platform, ev("auth.login"))
	}
	cfg := ForwarderConfig{Name: "remote", URL: srv.URL, Token: "tok"}
	if err := s.forwardOnce(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	_, _ = s.Append(ctx, identity.Platform, ev("auth.logout"))
	if err := s.forwardOnce(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if len(got) != 8 || VerifyChain(GenesisHash, got) != 0 {
		t.Fatalf("remote chain broken: %d", len(got))
	}
	st, _ := s.ForwardStatuses(ctx)
	if len(st) != 1 || st[0].LastSeq != 8 {
		t.Fatalf("%+v", st)
	}
}
