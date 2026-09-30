package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

const testDefault = `C:\ProgramData\OpenDeploy`

func TestServiceDataDirParsesServiceCommandLine(t *testing.T) {
	exe := `"C:\Program Files\OpenDeploy\bin\opendeploy-desktop.exe"`
	images := `--images "C:\Program Files\OpenDeploy\guest"`
	for _, tc := range []struct{ cmdline, want string }{
		{exe + ` run ` + images + ` --data A:\OpenDeploy`, `A:\OpenDeploy`},
		{exe + ` run ` + images + ` -data A:\OpenDeploy`, `A:\OpenDeploy`},
		{exe + ` run ` + images + ` --data=A:\OpenDeploy`, `A:\OpenDeploy`},
		{exe + ` run ` + images + ` -data=A:\OpenDeploy`, `A:\OpenDeploy`},
		{exe + ` run --data "D:\Open Deploy\node data" ` + images, `D:\Open Deploy\node data`},
		{exe + ` run --data="D:\Open Deploy" ` + images, `D:\Open Deploy`},
		{exe + ` run --data A:\OpenDeploy\ ` + images, `A:\OpenDeploy`},
		{exe + ` run --data A:\one --data A:\two`, `A:\two`}, // last wins, as in flag parsing
		{`C:\od\bin\opendeploy-desktop.exe run --images C:\od\guest`, testDefault},
		{exe + ` run`, testDefault},
		{exe, testDefault},
	} {
		got, err := serviceDataDir(tc.cmdline, testDefault)
		if err != nil || got != tc.want {
			t.Errorf("serviceDataDir(%s) = %q, %v; want %q", tc.cmdline, got, err, tc.want)
		}
	}
	// What install writes (EscapeArg, as mgr.CreateService does) reads back.
	written := quoteArgs([]string{`C:\Program Files\OpenDeploy\bin\opendeploy-desktop.exe`, "run",
		"--images", `C:\Program Files\OpenDeploy\guest`, "--data", `E:\My Data\OpenDeploy`})
	if got, err := serviceDataDir(written, testDefault); err != nil || got != `E:\My Data\OpenDeploy` {
		t.Errorf("round trip of %s = %q, %v", written, got, err)
	}
	for _, bad := range []string{exe + ` run --bogus`, exe + ` run --data=`, exe + ` run --data`} {
		if got, err := serviceDataDir(bad, testDefault); err == nil {
			t.Errorf("serviceDataDir(%s) = %q, want an error", bad, got)
		}
	}
}

// Regression test for F-3: without --data, install (the MSI and upgrades),
// uninstall and status used the default folder instead of the one the
// installed service runs with.
func TestChooseDataDirFollowsInstalledService(t *testing.T) {
	home := dataHome{Dir: `A:\OpenDeploy`, From: "The installed OpenDeploy service"}
	for _, cmd := range []string{"install", "uninstall", "status"} {
		got, err := chooseDataDir(cmd, testDefault, false, home, testDefault)
		if err != nil || got != `A:\OpenDeploy` {
			t.Errorf("%s without --data: %q, %v; want the service's folder A:\\OpenDeploy", cmd, got, err)
		}
		// The same folder spelled differently is not a move.
		got, err = chooseDataDir(cmd, `a:\opendeploy\`, true, home, testDefault)
		if err != nil || got != `A:\OpenDeploy` {
			t.Errorf("%s --data a:\\opendeploy\\: %q, %v", cmd, got, err)
		}
	}
}

func TestChooseDataDirRefusesMovingNodeData(t *testing.T) {
	home := dataHome{Dir: `A:\OpenDeploy`, From: "The installed OpenDeploy service"}
	_, err := chooseDataDir("install", `B:\Elsewhere`, true, home, testDefault)
	if err == nil || !strings.Contains(err.Error(), "not supported") || !strings.Contains(err.Error(), "uninstall --purge") ||
		!strings.Contains(err.Error(), `A:\OpenDeploy`) {
		t.Errorf("install to another folder: %v", err)
	}
	if _, err := chooseDataDir("uninstall", `B:\Elsewhere`, true, home, testDefault); err == nil {
		t.Error("uninstall --data for another folder than the service's was accepted")
	}
	// status only looks; an explicit folder is where it looks.
	if got, err := chooseDataDir("status", `B:\Elsewhere`, true, home, testDefault); err != nil || got != `B:\Elsewhere` {
		t.Errorf("status --data: %q, %v", got, err)
	}
}

func TestChooseDataDirFreshInstall(t *testing.T) {
	if got, err := chooseDataDir("install", `A:\OpenDeploy\ `, true, dataHome{}, testDefault); err != nil || got != `A:\OpenDeploy` {
		t.Errorf("fresh install --data: %q, %v", got, err)
	}
	if got, err := chooseDataDir("install", testDefault, false, dataHome{}, testDefault); err != nil || got != testDefault {
		t.Errorf("fresh install: %q, %v", got, err)
	}
}

// The MSI passes `install --data "[DATADIR] "`: the space keeps a trailing
// backslash in DATADIR from escaping the closing quote.
func TestMSIDataDirArgument(t *testing.T) {
	for datadir, want := range map[string]string{
		`A:\OpenDeploy`:    `A:\OpenDeploy`,
		`A:\OpenDeploy\`:   `A:\OpenDeploy`,
		`D:\Open Deploy\`:  `D:\Open Deploy`,
		`D:\Open Deploy\x`: `D:\Open Deploy\x`,
	} {
		args, err := windows.DecomposeCommandLine(`"C:\Program Files\OpenDeploy\bin\opendeploy-desktop.exe" install --data "` + datadir + ` "`)
		if err != nil || len(args) != 4 {
			t.Fatalf("%s: %q %v", datadir, args, err)
		}
		if got := normalizeDataDir(args[3]); got != want {
			t.Errorf("DATADIR=%s: --data %q, want %q", datadir, got, want)
		}
	}
}

var testSys = systemDirs{
	Windows:      `C:\Windows`,
	ProgramFiles: []string{`C:\Program Files`, `C:\Program Files (x86)`},
	Install:      `D:\Apps\OpenDeploy`,
	ProgramData:  `C:\ProgramData`,
	Profiles:     `C:\Users`,
}

func TestCheckDataDirPath(t *testing.T) {
	refused := map[string]string{
		"":                             "empty",
		`OpenDeploy`:                   "relative",
		`data\OpenDeploy`:              "relative",
		`\OpenDeploy`:                  "no drive",
		`C:OpenDeploy`:                 "drive-relative",
		`A:\`:                          "drive root",
		`a:`:                           "drive-relative root",
		`\\server\share\OpenDeploy`:    "UNC",
		`//server/share/OpenDeploy`:    "UNC",
		`\\?\C:\OpenDeploy`:            "device path",
		`\\.\C:\OpenDeploy`:            "device path",
		`C:\Windows`:                   "Windows",
		`c:\windows\System32\od`:       "inside Windows",
		`C:\Program Files`:             "Program Files",
		`C:\Program Files\OpenDeploy`:  "inside Program Files",
		`C:\Program Files (x86)\od`:    "inside Program Files (x86)",
		`D:\Apps\OpenDeploy\data`:      "inside the install folder",
		`D:\Apps`:                      "contains the install folder",
		`C:\ProgramData`:               "ProgramData itself",
		`C:\Users`:                     "profiles root",
		`C:\Users\alice`:               "a user profile",
		`C:\Users\Public\`:             "the public profile",
		`C:\Open"Deploy`:               "quote",
		`C:\OpenDeploy\data:stream`:    "stream",
		`C:\OpenDeploy\*`:              "wildcard",
		`  `:                           "blank",
		`C:\Users\..\Users\alice\.\.\`: "a user profile, uncleaned",
	}
	for dir, why := range refused {
		if err := checkDataDirPath(dir, testSys); err == nil {
			t.Errorf("%q (%s) was accepted", dir, why)
		}
	}
	for _, dir := range []string{`A:\OpenDeploy`, `A:\OpenDeploy\`, `C:\ProgramData\OpenDeploy`, `D:\Data\OpenDeploy`,
		`C:\Users\alice\OpenDeploy`, `E:\Open Deploy (node)`, `D:\AppsData\OpenDeploy`, `C:\WindowsData`} {
		if err := checkDataDirPath(dir, testSys); err != nil {
			t.Errorf("%q refused: %v", dir, err)
		}
	}
}

func TestCheckVolume(t *testing.T) {
	const acl = windows.FILE_PERSISTENT_ACLS
	for _, ok := range []struct {
		fs    string
		flags uint32
	}{{"NTFS", acl}, {"ReFS", acl | 0x2}} {
		if err := checkVolume(`A:\`, windows.DRIVE_FIXED, ok.fs, ok.flags); err != nil {
			t.Errorf("fixed %s refused: %v", ok.fs, err)
		}
	}
	for _, bad := range []struct {
		drive uint32
		fs    string
		flags uint32
	}{
		{windows.DRIVE_FIXED, "FAT32", 0},
		{windows.DRIVE_FIXED, "exFAT", 0},
		{windows.DRIVE_FIXED, "NTFS", 0}, // no persistent ACLs
		{windows.DRIVE_REMOTE, "NTFS", acl},
		{windows.DRIVE_REMOVABLE, "NTFS", acl},
		{windows.DRIVE_CDROM, "UDF", 0},
		{windows.DRIVE_RAMDISK, "NTFS", acl},
		{windows.DRIVE_NO_ROOT_DIR, "", 0},
		{windows.DRIVE_UNKNOWN, "", 0},
	} {
		if err := checkVolume(`A:\`, bad.drive, bad.fs, bad.flags); err == nil {
			t.Errorf("drive type %d %s (flags %#x) accepted", bad.drive, bad.fs, bad.flags)
		}
	}
}

func TestVolumeOfSystemDrive(t *testing.T) {
	// The system drive is always a fixed NTFS volume.
	if err := volumeOf(os.Getenv("SystemDrive") + `\OpenDeploy`); err != nil {
		t.Fatal(err)
	}
}

func junction(t *testing.T, link, target string) {
	t.Helper()
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}
}

func TestCheckDataDirContents(t *testing.T) {
	root := t.TempDir()
	if err := checkDataDirContents(filepath.Join(root, "new"), false); err != nil {
		t.Errorf("new folder: %v", err)
	}
	empty := filepath.Join(root, "empty")
	_ = os.Mkdir(empty, 0o755)
	if err := checkDataDirContents(empty, false); err != nil {
		t.Errorf("empty folder: %v", err)
	}
	used := filepath.Join(root, "used")
	_ = os.Mkdir(used, 0o755)
	_ = os.WriteFile(filepath.Join(used, "photo.jpg"), []byte("x"), 0o644)
	if err := checkDataDirContents(used, false); err == nil {
		t.Error("non-empty folder without the marker was accepted")
	}
	if err := checkDataDirContents(used, true); err != nil {
		t.Errorf("the existing node's own folder refused: %v", err)
	}
	if err := writeMarker(used); err != nil {
		t.Fatal(err)
	}
	if err := checkDataDirContents(used, false); err != nil {
		t.Errorf("marked data folder refused: %v", err)
	}
	file := filepath.Join(root, "file")
	_ = os.WriteFile(file, nil, 0o644)
	if err := checkDataDirContents(file, false); err == nil {
		t.Error("a file was accepted as the data folder")
	}
	link := filepath.Join(root, "link")
	junction(t, link, empty)
	if err := checkDataDirContents(link, false); err == nil {
		t.Error("a junction was accepted as the data folder")
	}
	// A directory named like the marker is not a marker.
	fake := filepath.Join(root, "fake")
	_ = os.MkdirAll(filepath.Join(fake, dataMarker), 0o755)
	if err := checkDataDirContents(fake, false); err == nil {
		t.Error("a folder with a directory named like the marker was accepted")
	}
}

func TestPurgeDeletesOnlyMarkedDataFolder(t *testing.T) {
	root := t.TempDir()
	def := filepath.Join(root, "default")
	unmarked := filepath.Join(root, "photos")
	_ = os.Mkdir(unmarked, 0o755)
	_ = os.WriteFile(filepath.Join(unmarked, "photo.jpg"), []byte("x"), 0o644)
	if err := purgeDataDir(unmarked, def, systemDirs{}); err == nil {
		t.Error("purge of a folder without the marker did not fail")
	}
	if _, err := os.Stat(filepath.Join(unmarked, "photo.jpg")); err != nil {
		t.Fatalf("purge deleted an unmarked folder: %v", err)
	}

	// A junction to a marked folder is not followed or deleted.
	marked := filepath.Join(root, "node")
	_ = os.Mkdir(marked, 0o755)
	_ = writeMarker(marked)
	_ = os.WriteFile(filepath.Join(marked, "status.json"), []byte("{}"), 0o644)
	link := filepath.Join(root, "link")
	junction(t, link, marked)
	if err := purgeDataDir(link, def, systemDirs{}); err == nil {
		t.Error("purge through a junction did not fail")
	}
	if _, err := os.Stat(filepath.Join(marked, "status.json")); err != nil {
		t.Fatalf("purge through a junction deleted the target: %v", err)
	}
	_ = os.Remove(link)

	if err := purgeDataDir(marked, def, systemDirs{}); err != nil {
		t.Fatalf("purge of a marked folder: %v", err)
	}
	if _, err := os.Stat(marked); !os.IsNotExist(err) {
		t.Fatalf("marked folder not deleted: %v", err)
	}

	// The default folder of a version that wrote no marker is deleted.
	_ = os.Mkdir(def, 0o755)
	_ = os.WriteFile(filepath.Join(def, "status.json"), []byte("{}"), 0o644)
	if err := purgeDataDir(def, def, systemDirs{}); err != nil {
		t.Fatalf("purge of the default folder: %v", err)
	}
	if _, err := os.Stat(def); !os.IsNotExist(err) {
		t.Fatalf("default folder not deleted: %v", err)
	}

	// Nothing to delete is fine; a dangerous path is refused even with the marker.
	if err := purgeDataDir(filepath.Join(root, "gone"), def, systemDirs{}); err != nil {
		t.Errorf("purge of a missing folder: %v", err)
	}
	if err := checkPurge(`C:\`, def, systemDirs{}); err == nil {
		t.Error("purge of a drive root allowed")
	}
	if err := checkPurge(`\\server\share\od`, def, systemDirs{}); err == nil {
		t.Error("purge of a network path allowed")
	}
}
