package backup

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var idRE = regexp.MustCompile(`^bkp_[0-9]{8}T[0-9]{6}Z_[0-9a-f]{8}$`)

// ValidID reports whether id is a backup id produced by NewID.
func ValidID(id string) bool { return idRE.MatchString(id) }

// StagingFile is where a service writes its export for a backup. Callers
// never choose paths: services derive them from the node's staging dir.
func StagingFile(dir, id, component string) (string, error) {
	if !ValidID(id) {
		return "", errors.New("invalid backup id")
	}
	if err := os.MkdirAll(dir, 0o770); err != nil {
		return "", err
	}
	return filepath.Join(dir, id+"-"+component), nil
}

// Shared gives a staging file the group-readable mode other services need
// (services run with umask 0077, which would otherwise strip it).
func Shared(path string) error { return os.Chmod(path, 0o640) }

// TarDir writes dir as a tar stream: regular files, directories and
// symlinks (stored, never followed). skip excludes relative paths.
func TarDir(w io.Writer, dir string, skip func(rel string) bool) error {
	tw := tar.NewWriter(w)
	err := filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil || rel == "." {
			return err
		}
		rel = filepath.ToSlash(rel)
		if skip != nil && skip(rel) {
			if fi.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		link := ""
		switch {
		case fi.Mode()&os.ModeSymlink != 0:
			if link, err = os.Readlink(p); err != nil {
				return err
			}
		case fi.IsDir(), fi.Mode().IsRegular():
		default:
			return nil
		}
		h, err := tar.FileInfoHeader(fi, link)
		if err != nil {
			return err
		}
		h.Name = rel
		if fi.IsDir() {
			h.Name += "/"
		}
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if fi.Mode().IsRegular() {
			f, err := os.Open(p)
			if err != nil {
				return err
			}
			_, err = io.Copy(tw, f)
			f.Close()
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	return tw.Close()
}

// UntarDir extracts a TarDir stream into dest, refusing absolute paths,
// traversal, links escaping dest and special files.
func UntarDir(r io.Reader, dest string) error {
	if err := os.MkdirAll(dest, 0o750); err != nil {
		return err
	}
	root, err := filepath.Abs(dest)
	if err != nil {
		return err
	}
	inside := func(p string) bool {
		return p == root || strings.HasPrefix(p, root+string(filepath.Separator))
	}
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		name := filepath.FromSlash(strings.TrimSuffix(h.Name, "/"))
		if filepath.IsAbs(name) || strings.Contains(h.Name, "..") {
			return fmt.Errorf("unsafe path in archive: %q", h.Name)
		}
		target := filepath.Join(root, name)
		if !inside(target) {
			return fmt.Errorf("unsafe path in archive: %q", h.Name)
		}
		// Parents must not be symlinks planted earlier in the archive.
		if parent, err := filepath.EvalSymlinks(filepath.Dir(target)); err == nil && !inside(parent) {
			return fmt.Errorf("archive path %q escapes via a symlink", h.Name)
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(h.Mode)&0o777|0o700); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(h.Mode)&0o777)
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
		case tar.TypeSymlink:
			lt := h.Linkname
			resolved := lt
			if !filepath.IsAbs(lt) {
				resolved = filepath.Join(filepath.Dir(target), lt)
			}
			if filepath.IsAbs(lt) || !inside(filepath.Clean(resolved)) {
				return fmt.Errorf("archive symlink %q -> %q escapes the destination", h.Name, lt)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
				return err
			}
			if err := os.Symlink(lt, target); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported archive entry %q", h.Name)
		}
	}
}
