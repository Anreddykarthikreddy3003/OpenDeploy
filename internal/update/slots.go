package update

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Slots manages A/B installs: <dir>/a and <dir>/b hold complete releases,
// <dir>/current is a symlink to the active one (swapped atomically), and
// <dir>/state.json records versions for rollback decisions.
type Slots struct{ Dir string }

// SlotState is persisted alongside the slots.
type SlotState struct {
	Active   string            `json:"active"`
	Previous string            `json:"previous,omitempty"`
	Versions map[string]string `json:"versions"`
	Schemas  map[string]int    `json:"schemas"`
	Staged   string            `json:"staged,omitempty"`
	Updated  time.Time         `json:"updated"`
}

// RequiredFiles must exist in every staged release.
var RequiredFiles = []string{"bin/platformd", "bin/opendeployctl"}

func (s *Slots) statePath() string { return filepath.Join(s.Dir, "state.json") }

// State reads the slot state (initialising slot "a" as active).
func (s *Slots) State() (*SlotState, error) {
	st := &SlotState{Active: "a", Versions: map[string]string{}, Schemas: map[string]int{}}
	b, err := os.ReadFile(s.statePath())
	if errors.Is(err, os.ErrNotExist) {
		if target, err := os.Readlink(filepath.Join(s.Dir, "current")); err == nil {
			st.Active = filepath.Base(target)
		}
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, st); err != nil {
		return nil, fmt.Errorf("slot state: %w", err)
	}
	if st.Versions == nil {
		st.Versions = map[string]string{}
	}
	if st.Schemas == nil {
		st.Schemas = map[string]int{}
	}
	return st, nil
}

func (s *Slots) save(st *SlotState) error {
	st.Updated = time.Now().UTC()
	b, _ := json.MarshalIndent(st, "", "  ")
	tmp := s.statePath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.statePath())
}

func other(slot string) string {
	if slot == "a" {
		return "b"
	}
	return "a"
}

// Stage extracts a release tarball (.tar.gz) into the inactive slot.
func (s *Slots) Stage(version string, schema int, tarball string) (string, error) {
	st, err := s.State()
	if err != nil {
		return "", err
	}
	slot := other(st.Active)
	dir := filepath.Join(s.Dir, slot)
	if err := os.RemoveAll(dir); err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	f, err := os.Open(tarball)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if err := extractRelease(f, dir); err != nil {
		os.RemoveAll(dir)
		return "", fmt.Errorf("stage %s: %w", version, err)
	}
	for _, req := range RequiredFiles {
		if fi, err := os.Stat(filepath.Join(dir, req)); err != nil || !fi.Mode().IsRegular() {
			os.RemoveAll(dir)
			return "", fmt.Errorf("stage %s: release is missing %s", version, req)
		}
	}
	st.Versions[slot], st.Schemas[slot], st.Staged = version, schema, slot
	return slot, s.save(st)
}

// extractRelease unpacks a release archive: regular files and directories
// only, no links, no traversal, sane sizes.
func extractRelease(r io.Reader, dir string) error {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	var total int64
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		name := filepath.Clean(strings.TrimPrefix(h.Name, "./"))
		if name == "." {
			continue
		}
		if filepath.IsAbs(name) || strings.HasPrefix(name, "..") {
			return fmt.Errorf("unsafe path %q", h.Name)
		}
		target := filepath.Join(dir, name)
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			total += h.Size
			if total > 2<<30 {
				return errors.New("release archive too large")
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			mode := os.FileMode(0o644)
			if h.Mode&0o111 != 0 {
				mode = 0o755
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
			if err != nil {
				return err
			}
			_, err = io.Copy(f, io.LimitReader(tr, h.Size))
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported entry %q in release archive", h.Name)
		}
	}
}

// Activate atomically points current at slot.
func (s *Slots) Activate(slot string) error {
	if slot != "a" && slot != "b" {
		return fmt.Errorf("invalid slot %q", slot)
	}
	if _, err := os.Stat(filepath.Join(s.Dir, slot)); err != nil {
		return fmt.Errorf("slot %s is empty", slot)
	}
	st, err := s.State()
	if err != nil {
		return err
	}
	tmp := filepath.Join(s.Dir, ".current-tmp")
	_ = os.Remove(tmp)
	if err := os.Symlink(slot, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(s.Dir, "current")); err != nil {
		return err
	}
	if st.Active != slot {
		st.Previous, st.Active = st.Active, slot
	}
	if st.Staged == slot {
		st.Staged = ""
	}
	return s.save(st)
}

// Hooks connect Apply to the host.
type Hooks struct {
	Restart func(ctx context.Context) error // restart all OpenDeploy services
	Healthy func(ctx context.Context) error // platform readiness (nil = ready)
	Backup  func(ctx context.Context) error // pre-migration backup (optional)
}

// Apply results.
var (
	ErrRolledBack   = errors.New("new release failed its readiness gate; rolled back to the previous release")
	ErrManualAction = errors.New("new release failed its readiness gate after a schema migration; automatic rollback is unsafe (restore the pre-update backup)")
)

// Apply switches to the staged slot, restarts, and waits for readiness.
// A release that migrates the schema forward cannot be rolled back
// automatically (the old binary may not read the new data): a backup is
// taken first and failures require operator action (PRD §18.2).
func (s *Slots) Apply(ctx context.Context, h Hooks, readiness time.Duration) error {
	st, err := s.State()
	if err != nil {
		return err
	}
	if st.Staged == "" {
		return errors.New("no staged release")
	}
	slot, prev := st.Staged, st.Active
	migrates := st.Schemas[slot] > st.Schemas[prev]
	if migrates && h.Backup != nil {
		if err := h.Backup(ctx); err != nil {
			return fmt.Errorf("pre-update backup failed; update aborted: %w", err)
		}
	}
	if err := s.Activate(slot); err != nil {
		return err
	}
	if err := h.Restart(ctx); err == nil {
		if waitHealthy(ctx, h.Healthy, readiness) == nil {
			return nil
		}
	}
	if migrates {
		return ErrManualAction
	}
	if err := s.Activate(prev); err != nil {
		return fmt.Errorf("rollback failed: %w", err)
	}
	_ = h.Restart(ctx)
	return ErrRolledBack
}

func waitHealthy(ctx context.Context, healthy func(context.Context) error, d time.Duration) error {
	deadline := time.Now().Add(d)
	var last error
	for time.Now().Before(deadline) {
		if last = healthy(ctx); last == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	if last == nil {
		last = errors.New("readiness timeout")
	}
	return last
}
