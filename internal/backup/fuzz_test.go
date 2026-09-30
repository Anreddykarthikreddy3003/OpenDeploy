package backup

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Restores read attacker-controllable objects from a remote bucket: none of
// the parsers may panic, accept an unsigned manifest, or write outside the
// restore directory.
func FuzzVerifyManifest(f *testing.F) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	signed, _ := Sign(&Manifest{ID: "20260101T000000Z-abcd", Version: "2.0.0"}, priv)
	f.Add(signed)
	f.Add([]byte(`{"manifest":{},"signature":""}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := VerifyManifest(b, pub)
		if err == nil && m == nil {
			t.Fatal("nil manifest without error")
		}
		if err == nil && !bytes.Equal(b, signed) && !strings.Contains(string(b), "signature") {
			t.Fatalf("unsigned document verified: %q", b)
		}
	})
}

func FuzzDecryptor(f *testing.F) {
	dek := bytes.Repeat([]byte{7}, 32)
	var ct bytes.Buffer
	enc, err := NewEncryptor(&ct, dek, "id", []byte("np01"))
	if err != nil {
		f.Fatal(err)
	}
	_, _ = enc.Write([]byte("backup payload"))
	_ = enc.Close()
	f.Add(ct.Bytes(), []byte("np01"))
	f.Add([]byte{0, 0, 0, 1, 2}, []byte("np01"))
	f.Add(ct.Bytes(), []byte("np")) // prefix comes from the manifest
	f.Fuzz(func(t *testing.T, b, prefix []byte) {
		d, err := NewDecryptor(bytes.NewReader(b), dek, "id", prefix)
		if err != nil {
			return
		}
		buf := make([]byte, 4096)
		for i := 0; i < 1<<12; i++ {
			if _, err := d.Read(buf); err != nil {
				return
			}
		}
	})
}

func FuzzUntarDir(f *testing.F) {
	var seed bytes.Buffer
	tw := tar.NewWriter(&seed)
	_ = tw.WriteHeader(&tar.Header{Name: "a/", Typeflag: tar.TypeDir, Mode: 0o755})
	_ = tw.WriteHeader(&tar.Header{Name: "a/f", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1})
	_, _ = tw.Write([]byte("x"))
	_ = tw.WriteHeader(&tar.Header{Name: "a/l", Typeflag: tar.TypeSymlink, Linkname: "f"})
	_ = tw.WriteHeader(&tar.Header{Name: "../evil", Typeflag: tar.TypeReg, Size: 0})
	tw.Close()
	f.Add(seed.Bytes())
	f.Fuzz(func(t *testing.T, b []byte) {
		parent := t.TempDir()
		dest := filepath.Join(parent, "restore")
		_ = UntarDir(bytes.NewReader(b), dest)
		entries, _ := os.ReadDir(parent)
		for _, e := range entries {
			if e.Name() != "restore" {
				t.Fatalf("wrote outside the restore dir: %s", e.Name())
			}
		}
		_ = filepath.Walk(dest, func(p string, fi os.FileInfo, err error) error {
			if err != nil || fi.Mode()&os.ModeSymlink == 0 {
				return nil
			}
			target, _ := os.Readlink(p)
			if !filepath.IsAbs(target) {
				target = filepath.Join(filepath.Dir(p), target)
			}
			if rel, err := filepath.Rel(dest, filepath.Clean(target)); err != nil || strings.HasPrefix(rel, "..") {
				t.Fatalf("symlink %s escapes to %s", p, target)
			}
			return nil
		})
	})
}
