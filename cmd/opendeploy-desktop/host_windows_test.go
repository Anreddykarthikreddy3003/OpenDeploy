package main

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Regression test for F-1: the account had only SeServiceLogonRight and
// nothing denied the other logon types.
func TestServiceAccountRightsDenyEveryOtherLogon(t *testing.T) {
	got := slices.Clone(serviceAccountRights())
	slices.Sort(got)
	want := []string{
		"SeDenyBatchLogonRight",
		"SeDenyInteractiveLogonRight",
		"SeDenyNetworkLogonRight",
		"SeDenyRemoteInteractiveLogonRight",
		"SeServiceLogonRight",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("service account rights = %q, want exactly %q", got, want)
	}
	for _, r := range got {
		if r != "SeServiceLogonRight" && !strings.HasPrefix(r, "SeDeny") {
			t.Errorf("right %s allows a logon", r)
		}
	}
}

// The rights reach LsaAddAccountRights as a contiguous LSA_UNICODE_STRING
// array: USHORT Length and MaximumLength in bytes, then the buffer pointer.
func TestLSAStringsLayout(t *testing.T) {
	rights := serviceAccountRights()
	arr, err := lsaStrings(rights)
	if err != nil {
		t.Fatal(err)
	}
	if len(arr) != len(rights) {
		t.Fatalf("%d strings for %d rights", len(arr), len(rights))
	}
	want := uintptr(8) // 2+2 bytes of lengths, a 4-byte pointer
	if unsafe.Sizeof(uintptr(0)) == 8 {
		want = 16 // 2+2 bytes of lengths, 4 of padding, an 8-byte pointer
	}
	if size := unsafe.Sizeof(arr[0]); size != want {
		t.Fatalf("LSA_UNICODE_STRING size %d, want %d", size, want)
	}
	for i, r := range rights {
		u := arr[i]
		if int(u.Length) != 2*len(r) || u.MaximumLength != u.Length+2 {
			t.Errorf("%s: Length %d MaximumLength %d", r, u.Length, u.MaximumLength)
		}
		if s := string(utf16.Decode(unsafe.Slice(u.Buffer, u.Length/2))); s != r {
			t.Errorf("element %d holds %q, want %q", i, s, r)
		}
	}
}

// The policy handle opens with the access removeAccountRights uses; it is
// available without elevation, so this checks the LsaOpenPolicy call itself.
func TestOpenPolicyLookupNames(t *testing.T) {
	policy, err := openPolicy(policyLookupNames)
	if err != nil {
		t.Fatal(err)
	}
	if st, _, _ := procLsaClose.Call(policy); st != 0 {
		t.Fatalf("LsaClose: %v", lsaError(st))
	}
	// removeAccountRights treats this error as "the account is already gone".
	if _, _, _, err := windows.LookupSID("", "opendeploy-no-such-account-for-test"); !errors.Is(err, windows.ERROR_NONE_MAPPED) {
		t.Fatalf("lookup of a missing account: %v, want ERROR_NONE_MAPPED", err)
	}
}
