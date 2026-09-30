package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/desktop"
)

// The node's data folder: its WSL disk (wsl\ext4.vhdx), status.json,
// desktop.log and the bootstrap token.
//
// Where an existing node keeps its data is read, in this order, from:
//  1. the installed service's own arguments (`run ... --data DIR` in the
//     SCM), the source of truth while the service exists;
//  2. HKLM\SOFTWARE\OpenDeploy DataDir, written by every install so that an
//     uninstall that keeps the data (Apps & features) followed by a
//     reinstall finds it again; only `uninstall --purge` removes it;
//  3. the default folder, when it holds a WSL disk from a version that
//     wrote no record.
//
// Without --data, install (and so an MSI upgrade or repair), status and
// uninstall follow that folder. Install refuses a different --data: moving
// node data is not supported, and it would leave the existing WSL disk
// behind.
//
// Install gives the folder a protected DACL and `uninstall --purge` deletes
// it, so a user-chosen folder must be a new or empty folder (or one that is
// already an OpenDeploy data folder) on a local NTFS or ReFS drive, and
// never a drive root, a network path or a system folder. Install marks the
// folder with a marker file; purge deletes only a marked folder, or the
// default folder, which older versions created without a marker.
const (
	dataMarker   = ".opendeploy-data"
	dataRegKey   = `SOFTWARE\OpenDeploy`
	dataRegValue = "DataDir"
	markerText   = "This folder holds the data of an OpenDeploy node: its WSL disk (wsl\\ext4.vhdx), status and logs.\r\n" +
		"Check where the node keeps its data with: opendeploy-desktop status\r\n" +
		"Delete the node and this folder with: opendeploy-desktop uninstall --purge\r\n"
)

func defaultDataDir() string { return filepath.Join(programData(), "OpenDeploy") }

// normalizeDataDir cleans a --data value. Surrounding spaces are dropped:
// Windows file names cannot end in a space, and the MSI passes
// `--data "[DATADIR] "` so that a trailing backslash in DATADIR does not
// escape the closing quote.
func normalizeDataDir(dir string) string {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return ""
	}
	return filepath.Clean(dir)
}

// samePath compares two folders the way Windows does (case-insensitively).
func samePath(a, b string) bool {
	a, b = normalizeDataDir(a), normalizeDataDir(b)
	return a != "" && strings.EqualFold(a, b)
}

// within reports whether p is base or a folder inside it.
func within(p, base string) bool {
	p, base = strings.ToLower(normalizeDataDir(p)), strings.ToLower(normalizeDataDir(base))
	if p == "" || base == "" {
		return false
	}
	return p == base || strings.HasPrefix(p, strings.TrimSuffix(base, `\`)+`\`)
}

// serviceDataDir reads the data folder from the installed service's command
// line (`"C:\...\opendeploy-desktop.exe" run --images DIR --data DIR`). The
// arguments are parsed with the same flags as `run`, so --data X, -data X,
// --data=X and -data=X all work and the last one wins; a service without
// --data runs with the default folder.
func serviceDataDir(cmdline, def string) (string, error) {
	args, err := windows.DecomposeCommandLine(cmdline)
	if err != nil {
		return "", fmt.Errorf("parse the service command line %q: %w", cmdline, err)
	}
	if len(args) < 2 {
		return def, nil
	}
	cfg := desktop.Config{DataDir: def}
	fs, _ := flagSet(args[1], &cfg, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args[2:]); err != nil {
		return "", fmt.Errorf("parse the service command line %q: %w", cmdline, err)
	}
	dir := normalizeDataDir(cfg.DataDir)
	if dir == "" {
		return "", fmt.Errorf("the service command line %q has an empty --data", cmdline)
	}
	return dir, nil
}

// dataHome is where an existing node keeps its data.
type dataHome struct {
	Dir  string // "" when there is no existing node
	From string // who says so, for messages
}

// chooseDataDir picks the data folder for cmd (install, uninstall or
// status). Without --data every command follows the existing node. With
// --data, a fresh install uses it and status looks there; install or
// uninstall for another folder than the existing node's is refused.
func chooseDataDir(cmd, requested string, explicit bool, home dataHome, def string) (string, error) {
	requested = normalizeDataDir(requested)
	switch {
	case home.Dir == "" && explicit:
		return requested, nil
	case home.Dir == "":
		return def, nil
	case !explicit || samePath(requested, home.Dir):
		return home.Dir, nil
	case cmd == "status":
		return requested, nil
	case cmd == "install":
		return "", fmt.Errorf("%s keeps the node's data in %s. Moving it to %s is not supported: "+
			"the node's WSL disk would be left behind. Either keep the current folder (install without --data, "+
			"or with --data %q), or delete the node and all of its data with `opendeploy-desktop uninstall --purge` "+
			"and then install with --data %q", home.From, home.Dir, requested, home.Dir, requested)
	default:
		return "", fmt.Errorf("%s keeps the node's data in %s, not %s: run %s without --data", home.From, home.Dir, requested, cmd)
	}
}

// systemDirs are folders the data folder must not be, contain or (for the
// first three) be inside.
type systemDirs struct {
	Windows      string   // C:\Windows
	ProgramFiles []string // C:\Program Files, C:\Program Files (x86)
	Install      string   // this program's install folder (the MSI's INSTALLFOLDER)
	ProgramData  string   // C:\ProgramData: a folder inside it is fine (the default is)
	Profiles     string   // C:\Users: a folder inside a profile is fine, a profile itself is not
}

// checkDataDirPath refuses folders where a protected DACL or a purge would
// do harm, or that the service cannot use.
func checkDataDirPath(dir string, sys systemDirs) error {
	raw := strings.TrimSpace(dir)
	switch {
	case raw == "":
		return errors.New("the data folder is empty; give an absolute path such as A:\\OpenDeploy")
	case strings.HasPrefix(raw, `\\`) || strings.HasPrefix(raw, `//`):
		return fmt.Errorf("%s is a network (UNC) or device path; the data folder must be on a local drive, such as A:\\OpenDeploy", raw)
	case !filepath.IsAbs(raw):
		return fmt.Errorf("%s is not an absolute path; give the full path, such as A:\\OpenDeploy", raw)
	}
	dir = normalizeDataDir(raw)
	vol := filepath.VolumeName(dir)
	if len(vol) != 2 || vol[1] != ':' {
		return fmt.Errorf("%s is not on a drive letter; the data folder must be on a local drive, such as A:\\OpenDeploy", dir)
	}
	if strings.ContainsAny(dir[len(vol):], `"<>|?*:`) {
		return fmt.Errorf("%s contains characters that are not allowed in a Windows folder name", dir)
	}
	if dir == vol+`\` {
		return fmt.Errorf("%s is a drive root; use a folder on it, such as %sOpenDeploy (uninstall --purge deletes the whole data folder)", dir, dir)
	}
	for _, d := range append([]string{sys.Windows, sys.Install}, sys.ProgramFiles...) {
		if d != "" && (within(dir, d) || within(d, dir)) {
			return fmt.Errorf("%s is, is inside, or contains the system or program folder %s; choose a folder of its own, such as %sOpenDeploy", dir, d, vol+`\`)
		}
	}
	if within(sys.ProgramData, dir) {
		return fmt.Errorf("%s is, or contains, %s; use a folder inside it, such as %s", dir, sys.ProgramData, filepath.Join(sys.ProgramData, "OpenDeploy"))
	}
	if sys.Profiles != "" && (within(sys.Profiles, dir) || samePath(filepath.Dir(dir), sys.Profiles)) {
		return fmt.Errorf("%s is, or contains, a user profile folder; choose a folder of its own, such as %sOpenDeploy", dir, vol+`\`)
	}
	return nil
}

// checkVolume requires a local fixed drive whose file system keeps
// permissions (NTFS or ReFS), so the protected DACL means something.
func checkVolume(root string, driveType uint32, fsName string, fsFlags uint32) error {
	switch driveType {
	case windows.DRIVE_FIXED:
	case windows.DRIVE_REMOTE:
		return fmt.Errorf("%s is a network drive; the data folder must be on a local fixed drive", root)
	case windows.DRIVE_UNKNOWN, windows.DRIVE_NO_ROOT_DIR:
		return fmt.Errorf("drive %s does not exist", root)
	default:
		return fmt.Errorf("%s is not a fixed local drive (removable, optical and RAM drives are not supported)", root)
	}
	if !(strings.EqualFold(fsName, "NTFS") || strings.EqualFold(fsName, "ReFS")) || fsFlags&windows.FILE_PERSISTENT_ACLS == 0 {
		return fmt.Errorf("%s is formatted %s; the data folder needs NTFS (or ReFS), whose permissions keep the node's data private", root, fsName)
	}
	return nil
}

// volumeOf checks the drive that holds dir.
func volumeOf(dir string) error {
	root := filepath.VolumeName(normalizeDataDir(dir)) + `\`
	p, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return err
	}
	dt := windows.GetDriveType(p)
	if dt != windows.DRIVE_FIXED {
		return checkVolume(root, dt, "", 0)
	}
	var name [windows.MAX_PATH + 1]uint16
	var flags uint32
	if err := windows.GetVolumeInformation(p, nil, 0, nil, nil, &flags, &name[0], uint32(len(name))); err != nil {
		return fmt.Errorf("read the file system of %s: %w", root, err)
	}
	return checkVolume(root, dt, windows.UTF16ToString(name[:]), flags)
}

func hasMarker(dir string) bool {
	fi, err := os.Lstat(filepath.Join(dir, dataMarker))
	return err == nil && fi.Mode().IsRegular()
}

// plainDir reports whether an existing path is a real folder, not a file, a
// symbolic link or a junction.
func plainDir(fi os.FileInfo) bool {
	return fi.IsDir() && fi.Mode()&(os.ModeSymlink|os.ModeIrregular) == 0
}

// checkDataDirContents accepts a folder that does not exist yet, an empty
// folder, an OpenDeploy data folder (marker present), or, when ours is set,
// the folder the existing node already uses (older versions wrote no
// marker). Anything else would get its permissions replaced and could be
// deleted by a purge.
func checkDataDirContents(dir string, ours bool) error {
	fi, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !plainDir(fi) {
		return fmt.Errorf("%s is not a plain folder (it is a file, a link or a junction); choose a new or empty folder", dir)
	}
	if ours || hasMarker(dir) {
		return nil
	}
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	names, err := f.Readdirnames(1)
	f.Close()
	if len(names) > 0 {
		return fmt.Errorf("%s is not empty and is not an OpenDeploy data folder (it has no %s file); choose a new or empty folder", dir, dataMarker)
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

// validateDataDir checks the folder install is about to use (not the drive:
// see volumeOf).
func validateDataDir(dir string, sys systemDirs, ours bool) error {
	if err := checkDataDirPath(dir, sys); err != nil {
		return err
	}
	return checkDataDirContents(dir, ours)
}

// checkPurge decides whether `uninstall --purge` may delete dir: a folder
// that passes the path checks and carries the marker, or the default
// folder. A folder that does not exist needs nothing.
func checkPurge(dir, def string, sys systemDirs) error {
	if err := checkDataDirPath(dir, sys); err != nil {
		return fmt.Errorf("not deleting %s: %w", dir, err)
	}
	fi, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !plainDir(fi) {
		return fmt.Errorf("not deleting %s: it is not a plain folder (a file, a link or a junction)", dir)
	}
	if !hasMarker(dir) && !samePath(dir, def) {
		return fmt.Errorf("not deleting %s: it has no %s file, so it may not be an OpenDeploy data folder; check it and delete it by hand", dir, dataMarker)
	}
	return nil
}

// purgeDataDir deletes the data folder, only if checkPurge allows it.
func purgeDataDir(dir, def string, sys systemDirs) error {
	if err := checkPurge(dir, def, sys); err != nil {
		return err
	}
	return os.RemoveAll(dir)
}

func writeMarker(dir string) error {
	return os.WriteFile(filepath.Join(dir, dataMarker), []byte(markerText), 0o644)
}

// hostSystemDirs returns this machine's system folders.
func hostSystemDirs() systemDirs {
	known := func(id *windows.KNOWNFOLDERID, env string) string {
		if p, err := windows.KnownFolderPath(id, 0); err == nil && p != "" {
			return p
		}
		if env == "" {
			return ""
		}
		return os.Getenv(env)
	}
	s := systemDirs{
		Windows: known(windows.FOLDERID_Windows, "SystemRoot"),
		ProgramFiles: []string{known(windows.FOLDERID_ProgramFiles, "ProgramFiles"),
			known(windows.FOLDERID_ProgramFilesX86, "ProgramFiles(x86)"), os.Getenv("ProgramW6432")},
		ProgramData: known(windows.FOLDERID_ProgramData, "ProgramData"),
		Profiles:    known(windows.FOLDERID_UserProfiles, ""),
	}
	if s.Profiles == "" && os.Getenv("PUBLIC") != "" {
		s.Profiles = filepath.Dir(os.Getenv("PUBLIC"))
	}
	// The MSI layout is <INSTALLFOLDER>\bin\opendeploy-desktop.exe.
	if exe, err := os.Executable(); err == nil && strings.EqualFold(filepath.Base(filepath.Dir(exe)), "bin") {
		s.Install = filepath.Dir(filepath.Dir(exe))
	}
	return s
}

// serviceCommandLine returns the installed service's BinaryPathName. It
// needs only read access to the service configuration, so status works
// without elevation.
func serviceCommandLine() (string, bool, error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return "", false, err
	}
	defer windows.CloseServiceHandle(scm)
	name, err := windows.UTF16PtrFromString(serviceName)
	if err != nil {
		return "", false, err
	}
	h, err := windows.OpenService(scm, name, windows.SERVICE_QUERY_CONFIG)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	s := &mgr.Service{Name: serviceName, Handle: h}
	defer s.Close()
	c, err := s.Config()
	if err != nil {
		return "", false, err
	}
	return c.BinaryPathName, true, nil
}

// keptDataDir reads the folder recorded by the last install ("" if none).
func keptDataDir() (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, dataRegKey, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if errors.Is(err, registry.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	defer k.Close()
	v, _, err := k.GetStringValue(dataRegValue)
	if errors.Is(err, registry.ErrNotExist) {
		return "", nil
	}
	return normalizeDataDir(v), err
}

func recordDataDir(dir string) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, dataRegKey, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue(dataRegValue, dir)
}

func forgetDataDir() {
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, dataRegKey, registry.SET_VALUE|registry.WOW64_64KEY); err == nil {
		_ = k.DeleteValue(dataRegValue)
		k.Close()
	}
	_ = registry.DeleteKey(registry.LOCAL_MACHINE, dataRegKey) // only succeeds once empty
}

// existingHome finds where an existing node keeps its data.
func existingHome(def string) (dataHome, error) {
	cmdline, installed, err := serviceCommandLine()
	if err != nil {
		return dataHome{}, fmt.Errorf("read the OpenDeploy service configuration: %w", err)
	}
	if installed {
		dir, err := serviceDataDir(cmdline, def)
		return dataHome{Dir: dir, From: "The installed OpenDeploy service"}, err
	}
	kept, err := keptDataDir()
	if err != nil {
		return dataHome{}, fmt.Errorf(`read HKLM\%s: %w`, dataRegKey, err)
	}
	if kept != "" {
		return dataHome{Dir: kept, From: "An earlier OpenDeploy install (its data was kept at uninstall)"}, nil
	}
	// A version that kept no record left its WSL disk in the default folder
	// (readable only by administrators: a permission error means it exists).
	if _, err := os.Stat(filepath.Join(def, "wsl", "ext4.vhdx")); err == nil || errors.Is(err, fs.ErrPermission) {
		return dataHome{Dir: def, From: "An earlier OpenDeploy install (its data was kept at uninstall)"}, nil
	}
	return dataHome{}, nil
}

// resolveDataDir sets cfg.DataDir for install, uninstall and status.
func resolveDataDir(cmd string, cfg *desktop.Config, explicit bool) error {
	def := defaultDataDir()
	home, err := existingHome(def)
	if err != nil {
		return err
	}
	dir, err := chooseDataDir(cmd, cfg.DataDir, explicit, home, def)
	if err != nil {
		return err
	}
	cfg.DataDir = dir
	return nil
}
