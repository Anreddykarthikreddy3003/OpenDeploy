//go:build unix

package builder

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// Packaged services run with UMask=0077; hand-off files must still end up
// group-readable for artifactd.
func TestShareTreeUnderStrictUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	hand := filepath.Join(t.TempDir(), "dep")
	_ = os.MkdirAll(filepath.Join(hand, "blobs"), 0o750)
	_ = os.WriteFile(filepath.Join(hand, "blobs", "layer"), []byte("x"), 0o640)
	_ = os.Symlink("/etc/passwd", filepath.Join(hand, "link"))
	if fi, _ := os.Stat(filepath.Join(hand, "blobs", "layer")); fi.Mode().Perm() != 0o600 {
		t.Fatalf("precondition: umask not applied (%v)", fi.Mode())
	}
	if err := shareTree(hand); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]os.FileMode{hand: 0o750, filepath.Join(hand, "blobs"): 0o750, filepath.Join(hand, "blobs", "layer"): 0o640} {
		if fi, _ := os.Stat(p); fi.Mode().Perm() != want {
			t.Errorf("%s: %v, want %v", p, fi.Mode().Perm(), want)
		}
	}
	if fi, _ := os.Stat("/etc/passwd"); fi.Mode().Perm() != 0o644 {
		t.Fatal("symlink target modified")
	}
}
