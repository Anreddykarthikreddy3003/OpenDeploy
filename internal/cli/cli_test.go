package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"flag"
	"io"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestParseFlagsAfterPositionals(t *testing.T) {
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	env := fs.String("env", "production", "")
	f := fs.Bool("f", false, "")
	pos, err := parse(fs, []string{"proj", "--env", "staging", "dir", "-f"})
	if err != nil || len(pos) != 2 || pos[0] != "proj" || pos[1] != "dir" || *env != "staging" || !*f {
		t.Fatalf("%v %v %s %v", pos, err, *env, *f)
	}
}

func TestSourceArchiveExcludesSecretsAndVCS(t *testing.T) {
	d := t.TempDir()
	must := func(p, c string) {
		_ = os.MkdirAll(filepath.Dir(filepath.Join(d, p)), 0o755)
		if err := os.WriteFile(filepath.Join(d, p), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	must("index.html", "hi")
	must("src/app.js", "x")
	must(".git/config", "secret")
	must("node_modules/a/index.js", "dep")
	must(".env", "TOKEN=1")
	must(".env.local", "TOKEN=2")
	must("certs/server.key", "key")
	must("tmp/cache.bin", "c")
	must(".opendeployignore", "tmp\n# comment\n")
	_ = os.Symlink("src/app.js", filepath.Join(d, "link.js"))
	var buf bytes.Buffer
	n, err := writeSourceArchive(&buf, d)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(zr)
	var names []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
	}
	sort.Strings(names)
	want := []string{".opendeployignore", "certs", "index.html", "link.js", "src", "src/app.js"} // certs/server.key itself is excluded
	if len(names) != len(want) {
		t.Fatalf("archive entries %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("archive entries %v, want %v", names, want)
		}
	}
	if n != 3 {
		t.Fatalf("file count %d", n)
	}
}
