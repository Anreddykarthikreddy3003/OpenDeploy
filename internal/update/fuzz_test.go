package update

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// extractRelease runs as root in hostd on archives that passed TUF
// verification; it is still hardened against hostile archives (defence in
// depth against a compromised signing key): nothing outside the slot, no
// links, no special files.
func FuzzExtractRelease(f *testing.F) {
	f.Add(releaseTarball(&testing.T{}, map[string]string{"bin/platformd": "x", "bin/opendeployctl": "y"}, nil))
	f.Add(releaseTarball(&testing.T{}, map[string]string{"../../etc/cron.d/x": "pwn"}, nil))
	f.Add(releaseTarball(&testing.T{}, nil, func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{Name: "bin/evil", Typeflag: tar.TypeSymlink, Linkname: "/etc/shadow"})
	}))
	f.Fuzz(func(t *testing.T, b []byte) {
		parent := t.TempDir()
		slot := filepath.Join(parent, "b")
		_ = os.MkdirAll(slot, 0o755)
		_ = extractRelease(bytes.NewReader(b), slot)
		entries, _ := os.ReadDir(parent)
		if len(entries) != 1 {
			t.Fatalf("wrote outside the slot: %v", entries)
		}
		_ = filepath.Walk(slot, func(p string, fi os.FileInfo, err error) error {
			if err == nil && !fi.Mode().IsRegular() && !fi.IsDir() {
				t.Fatalf("non-regular file extracted: %s (%v)", p, fi.Mode())
			}
			return nil
		})
	})
}

func FuzzParseVersion(f *testing.F) {
	for _, s := range []string{"2.1.0", "v2.1.0-rc.1", "0.0.1-next", "1.2", "", "v"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		v, err := ParseVersion(s)
		if err != nil {
			return
		}
		// Parsing is stable: a parsed version compares equal to itself
		// re-parsed from its canonical form.
		w, err := ParseVersion(strings.TrimPrefix(s, "v"))
		if err != nil || v.Less(w) || w.Less(v) {
			t.Fatalf("%q: unstable parse (%v)", s, err)
		}
	})
}
