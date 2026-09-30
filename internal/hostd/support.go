package hostd

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/hostops"
)

// Redaction patterns for support bundles: tokens, keys, passwords and
// connection strings never leave the node in diagnostics.
var redactions = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key|authorization)(["'\s:=]+)[^\s"',]+`),
	regexp.MustCompile(`od[tsp]_[A-Za-z0-9_-]{16,}`),
	regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}`),
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)[a-z]+://[^\s:/@]+:[^\s@/]+@`),
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
}

// Redact removes credentials from diagnostic text.
func Redact(b []byte) []byte {
	for _, re := range redactions {
		b = re.ReplaceAllFunc(b, func(m []byte) []byte {
			if sub := re.FindSubmatch(m); len(sub) == 3 {
				return append(append(append([]byte{}, sub[1]...), sub[2]...), []byte("[REDACTED]")...)
			}
			return []byte("[REDACTED]")
		})
	}
	return b
}

// SupportBundle collects redacted diagnostics into a tarball readable by
// platformd (so an owner can download it from the dashboard).
func (h *Host) SupportBundle(ctx context.Context) (*hostops.SupportBundle, error) {
	dir := filepath.Join(h.Node.DataDir, "support")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	p := filepath.Join(dir, "support-"+time.Now().UTC().Format("20060102T150405Z")+".tar.gz")
	f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, err
	}
	hs := sha256.New()
	zw := gzip.NewWriter(io.MultiWriter(f, hs))
	tw := tar.NewWriter(zw)
	add := func(name string, b []byte) {
		b = Redact(b)
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o640, Size: int64(len(b)), ModTime: time.Now()})
		_, _ = tw.Write(b)
	}
	info, _ := json.MarshalIndent(h.Info(), "", "  ")
	add("host-info.json", info)
	st, _ := json.MarshalIndent(h.State(), "", "  ")
	add("update-state.json", st)
	if b, err := os.ReadFile(configPathGuess()); err == nil {
		add("node.yaml", b)
	}
	for _, svc := range sortedUnits() {
		unit := hostopsUnit(svc)
		if out, err := h.Systemctl(ctx, "show", unit); err == nil {
			add("services/"+svc+".status", []byte(out))
		}
		c, cancel := context.WithTimeout(ctx, 20*time.Second)
		out, _ := exec.CommandContext(c, "/usr/bin/journalctl", "--no-pager", "-o", "short-iso", "-n", "300", "-u", unit).Output()
		cancel()
		add("logs/"+svc+".log", out)
	}
	if err := tw.Close(); err != nil {
		f.Close()
		return nil, err
	}
	if err := zw.Close(); err != nil {
		f.Close()
		return nil, err
	}
	fi, _ := f.Stat()
	f.Close()
	return &hostops.SupportBundle{Path: p, Size: fi.Size(), SHA256: hex.EncodeToString(hs.Sum(nil))}, nil
}

func hostopsUnit(svc string) string { return hostops.Units[svc] }

func configPathGuess() string {
	if p := os.Getenv("OPENDEPLOY_CONFIG"); p != "" {
		return p
	}
	return "/etc/opendeploy/node.yaml"
}
