package testcap

import "testing"

type recorder struct {
	testing.TB
	skipped, failed string
}

func (r *recorder) Helper()           {}
func (r *recorder) Skip(args ...any)  { r.skipped = args[0].(string) }
func (r *recorder) Fatal(args ...any) { r.failed = args[0].(string) }

func TestBlocked(t *testing.T) {
	t.Setenv(EnvRequire, "")
	r := &recorder{}
	Blocked(r, "no %s", "runsc")
	if r.skipped != "CAPABILITY-BLOCKED: no runsc" || r.failed != "" {
		t.Fatalf("%+v", r)
	}
	t.Setenv(EnvRequire, "1")
	r = &recorder{}
	Blocked(r, "no %s", "runsc")
	if r.failed == "" || r.skipped != "" {
		t.Fatalf("required capability was skipped: %+v", r)
	}
}
