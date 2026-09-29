// Package testcap reports a test the host cannot run (PRD §30.1): a control
// that is capability-blocked is never silently passed. Where the host is
// expected to have every capability (the release-gate runners set
// OPENDEPLOY_REQUIRE_CAPS=1) a missing capability fails the test instead.
package testcap

import (
	"fmt"
	"os"
	"testing"
)

// EnvRequire names the variable that turns capability skips into failures.
const EnvRequire = "OPENDEPLOY_REQUIRE_CAPS"

// Required reports whether this run must not skip for missing capabilities.
func Required() bool { return os.Getenv(EnvRequire) == "1" }

// Blocked skips t with a CAPABILITY-BLOCKED reason, or fails it when
// capabilities are required.
func Blocked(t testing.TB, format string, args ...any) {
	t.Helper()
	msg := "CAPABILITY-BLOCKED: " + fmt.Sprintf(format, args...)
	if Required() {
		t.Fatal(msg + " (" + EnvRequire + "=1)")
		return
	}
	t.Skip(msg)
}
