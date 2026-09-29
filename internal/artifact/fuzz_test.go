package artifact

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Build output is produced by user-controlled code: artifactd must reject
// or safely store any tar it is handed, never writing outside its store.
func FuzzIngestStatic(f *testing.F) {
	f.Add(staticTar([]tar.Header{{Name: "index.html", Typeflag: tar.TypeReg}}, map[string]string{"index.html": "hi"}).Bytes())
	f.Add(staticTar([]tar.Header{{Name: "../x", Typeflag: tar.TypeReg}, {Name: "l", Typeflag: tar.TypeSymlink, Linkname: "/etc"}}, map[string]string{"../x": "y"}).Bytes())
	f.Fuzz(func(t *testing.T, b []byte) {
		parent := t.TempDir()
		st, err := NewStore(filepath.Join(parent, "store"), Limits{MaxBlobBytes: 1 << 20, MaxTotalBytes: 1 << 20, MaxStaticFiles: 100, MaxLayers: 8})
		if err != nil {
			t.Fatal(err)
		}
		info, err := st.IngestStatic(bytes.NewReader(b))
		assertContained(t, parent)
		if err == nil && !strings.HasPrefix(st.StaticDir(info.Digest), st.Root) {
			t.Fatalf("static dir outside the store: %s", st.StaticDir(info.Digest))
		}
	})
}

func FuzzIngestOCILayout(f *testing.F) {
	var seed bytes.Buffer
	tw := tar.NewWriter(&seed)
	for name, body := range map[string]string{"oci-layout": `{"imageLayoutVersion":"1.0.0"}`, "index.json": `{"schemaVersion":2,"manifests":[]}`} {
		_ = tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))})
		_, _ = tw.Write([]byte(body))
	}
	tw.Close()
	f.Add(seed.Bytes())
	f.Fuzz(func(t *testing.T, b []byte) {
		parent := t.TempDir()
		st, err := NewStore(filepath.Join(parent, "store"), Limits{MaxBlobBytes: 1 << 20, MaxTotalBytes: 1 << 20, MaxStaticFiles: 100, MaxLayers: 8})
		if err != nil {
			t.Fatal(err)
		}
		_, _ = st.IngestOCILayout(bytes.NewReader(b))
		assertContained(t, parent)
	})
}

// assertContained checks nothing but the store was created under parent and
// the store holds no symlinks.
func assertContained(t *testing.T, parent string) {
	t.Helper()
	entries, _ := os.ReadDir(parent)
	if len(entries) != 1 || entries[0].Name() != "store" {
		t.Fatalf("wrote outside the store: %v", entries)
	}
	_ = filepath.Walk(filepath.Join(parent, "store"), func(p string, fi os.FileInfo, err error) error {
		if err == nil && fi.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("symlink stored: %s", p)
		}
		return nil
	})
}
