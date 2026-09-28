package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/model"
)

func TestPassword(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$") {
		t.Fatal(h)
	}
	if !VerifyPassword(h, "correct horse battery") || VerifyPassword(h, "wrong horse battery") {
		t.Fatal("verify")
	}
	if VerifyPassword("", "anything") {
		t.Fatal("empty hash verified")
	}
	if _, err := HashPassword("short"); err == nil {
		t.Fatal("short password accepted")
	}
	if VerifyPassword("$argon2id$v=19$m=999999999,t=1,p=1$c2FsdA$aGFzaA", "x") {
		t.Fatal("absurd params accepted")
	}
}

// RFC 6238 test vector (SHA1, T=59 -> 94287082 truncated to 6 digits 287082).
func TestTOTPVector(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // "12345678901234567890"
	c, _ := TOTPCode(secret, time.Unix(59, 0))
	if c != "287082" {
		t.Fatalf("got %s", c)
	}
}

func TestTOTPReplay(t *testing.T) {
	s := NewTOTPSecret()
	now := time.Now()
	code, _ := TOTPCode(s, now)
	step, ok := VerifyTOTP(s, code, now, 0)
	if !ok {
		t.Fatal("valid code rejected")
	}
	if _, ok := VerifyTOTP(s, code, now, step); ok {
		t.Fatal("replayed code accepted")
	}
	old, _ := TOTPCode(s, now.Add(-5*time.Minute))
	if _, ok := VerifyTOTP(s, old, now, 0); ok && old != code {
		t.Fatal("stale code accepted")
	}
	if _, ok := VerifyTOTP(s, "12345a", now, 0); ok {
		t.Fatal("non-numeric accepted")
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes, hashes := NewRecoveryCodes(10)
	if len(codes) != 10 || HashRecoveryCode(strings.ToUpper(codes[3])) != hashes[3] {
		t.Fatal("recovery normalisation")
	}
}

func TestSealer(t *testing.T) {
	s, _ := NewSealer(make([]byte, 32))
	ct, _ := s.Seal([]byte("seed"), "user:1")
	if p, err := s.Open(ct, "user:1"); err != nil || string(p) != "seed" {
		t.Fatal(err)
	}
	if _, err := s.Open(ct, "user:2"); err == nil {
		t.Fatal("aad not bound")
	}
}

// ST-06 role matrix (PRD §15.2).
func TestRBACMatrix(t *testing.T) {
	type c struct {
		global, project, cap string
		a                    Action
		want                 bool
	}
	cases := []c{
		{model.RoleViewer, model.RoleViewer, "", ProjectRead, true},
		{model.RoleViewer, model.RoleViewer, "", DeployCreate, false},
		{model.RoleViewer, model.RoleViewer, "", SecretsList, false},
		{model.RoleDeveloper, model.RoleDeveloper, "", DeployRollback, true},
		{model.RoleDeveloper, model.RoleDeveloper, "", SecretsReveal, false},
		{model.RoleDeveloper, model.RoleDeveloper, "", MembersManage, false},
		{model.RoleDeveloper, model.RoleDeveloper, "", CapabilityGrant, false},
		{model.RoleAdmin, model.RoleAdmin, "", SecretsReveal, true},
		{model.RoleAdmin, model.RoleAdmin, "", CapabilityGrant, false},
		{model.RoleAdmin, "", "", ProjectRead, false}, // not a member of this project
		{model.RoleOwner, "", "", CapabilityGrant, true},
		{model.RoleOwner, "", model.RoleViewer, DeployCreate, false}, // token capped
		{model.RoleAdmin, model.RoleAdmin, model.RoleDeveloper, SecretsWrite, false},
	}
	for i, k := range cases {
		if got := AllowedProject(k.global, k.project, k.cap, k.a); got != k.want {
			t.Errorf("case %d %+v: got %v", i, k, got)
		}
	}
	if AllowedNode(model.RoleAdmin, "", UpdateManage) || !AllowedNode(model.RoleOwner, "", UpdateManage) {
		t.Fatal("update is owner only")
	}
	if !AllowedNode(model.RoleAdmin, "", ProjectCreate) || AllowedNode(model.RoleDeveloper, "", ProjectCreate) {
		t.Fatal("project create")
	}
	if AllowedProject(model.RoleOwner, "", "", Action("host.shell")) {
		t.Fatal("unknown action allowed")
	}
	if !Sensitive(SecretsReveal) || Sensitive(ProjectRead) {
		t.Fatal("sensitivity")
	}
}
