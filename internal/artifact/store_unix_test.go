//go:build unix

package artifact

import (
	"archive/tar"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// Under the packaged umask (0077) static artifacts must still be readable
// by the edge, while the rest of the store stays private.
func TestStaticArtifactReadableByEdgeUnderStrictUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	st := newStore(t)
	buf := staticTar([]tar.Header{{Name: "assets/", Typeflag: tar.TypeDir}, {Name: "assets/app.js", Typeflag: tar.TypeReg}, {Name: "index.html", Typeflag: tar.TypeReg, Mode: 0o600}},
		map[string]string{"assets/app.js": "js", "index.html": "hi"})
	info, err := st.IngestStatic(buf)
	if err != nil {
		t.Fatal(err)
	}
	root, dir := st.Root, st.StaticDir(info.Digest)
	for p, want := range map[string]os.FileMode{
		root: 0o711, filepath.Join(root, "static"): 0o711, dir: 0o755,
		filepath.Join(dir, "assets"): 0o755, filepath.Join(dir, "assets", "app.js"): 0o644, filepath.Join(dir, "index.html"): 0o644,
	} {
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != want {
			t.Errorf("%s: %v %v, want %v", p, fi.Mode().Perm(), err, want)
		}
	}
	if fi, _ := os.Stat(filepath.Join(root, "blobs")); fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("blobs readable by others: %v", fi.Mode())
	}
}
