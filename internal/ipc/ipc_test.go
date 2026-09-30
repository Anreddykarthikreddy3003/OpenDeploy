package ipc

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type echoReq struct {
	Msg string `json:"msg"`
}
type echoResp struct {
	Msg    string `json:"msg"`
	Caller string `json:"caller"`
}

func start(t *testing.T, ids *IdentityMap, allowed []string) *Client {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "s.sock")
	s := NewServer("test", ids, nil)
	Handle(s, "echo", allowed, func(ctx context.Context, c Caller, r echoReq) (echoResp, error) {
		if r.Msg == "nf" {
			return echoResp{}, Errorf(CodeNotFound, "missing")
		}
		return echoResp{Msg: r.Msg, Caller: c.Identity}, nil
	})
	if err := s.Listen(sock, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go s.Serve(ctx)
	time.Sleep(20 * time.Millisecond)
	return NewClient(sock)
}

func TestPeerCredIdentity(t *testing.T) {
	uid := uint32(os.Getuid())
	c := start(t, NewIdentityMap(map[uint32]string{uid: "platformd"}), []string{"platformd"})
	r, err := Call[echoReq, echoResp](context.Background(), c, "echo", echoReq{Msg: "hi"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Caller != "platformd" || r.Msg != "hi" {
		t.Fatalf("%+v", r)
	}
	if _, err := Call[echoReq, echoResp](context.Background(), c, "echo", echoReq{Msg: "nf"}); !IsCode(err, CodeNotFound) {
		t.Fatalf("got %v", err)
	}
}

func TestDeniedIdentity(t *testing.T) {
	uid := uint32(os.Getuid())
	c := start(t, NewIdentityMap(map[uint32]string{uid: "builderd"}), []string{"platformd"})
	if _, err := Call[echoReq, echoResp](context.Background(), c, "echo", echoReq{Msg: "hi"}); !IsCode(err, CodeForbidden) {
		t.Fatalf("builderd must be denied, got %v", err)
	}
}

func TestDeclaredIdentityIgnoredOutsideDevMode(t *testing.T) {
	c := start(t, NewIdentityMap(nil), []string{"platformd"})
	if _, err := Call[echoReq, echoResp](context.Background(), c.WithDevIdentity("platformd"), "echo", echoReq{}); !IsCode(err, CodeForbidden) {
		t.Fatalf("declared identity must be ignored, got %v", err)
	}
}

func TestUnknownOpAndFields(t *testing.T) {
	uid := uint32(os.Getuid())
	c := start(t, NewIdentityMap(map[uint32]string{uid: "platformd"}), []string{"platformd"})
	if _, err := Call[echoReq, echoResp](context.Background(), c, "exec", echoReq{}); err == nil {
		t.Fatal("unknown op must fail")
	}
	type extra struct {
		Msg string `json:"msg"`
		Cmd string `json:"cmd"`
	}
	if _, err := Call[extra, echoResp](context.Background(), c, "echo", extra{Cmd: "rm -rf /"}); !IsCode(err, CodeBadRequest) {
		t.Fatalf("unknown field must be rejected, got %v", err)
	}
}

func TestHealthy(t *testing.T) {
	// Any local caller may probe health, even one with no identity.
	c := start(t, NewIdentityMap(map[uint32]string{}), []string{"platformd"})
	if err := c.Healthy(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := NewClient(filepath.Join(t.TempDir(), "gone.sock")).Healthy(context.Background()); err == nil {
		t.Fatal("missing server reported healthy")
	}
}
