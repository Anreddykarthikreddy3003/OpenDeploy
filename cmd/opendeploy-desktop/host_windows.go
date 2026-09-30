package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/desktop"
)

// WSL distributions are registered per user and WSL does not run under
// LocalSystem, so the service runs as a dedicated local account that exists
// only for this purpose: a standard user, hidden from the sign-in screen,
// with a random password that is never stored. It may log on only as a
// service; every other logon type is denied (serviceAccountRights).
const (
	serviceName    = "OpenDeploy"
	serviceAccount = "opendeploy-svc"
	distroName     = "OpenDeploy"
)

func programData() string {
	if p := os.Getenv("ProgramData"); p != "" {
		return p
	}
	return `C:\ProgramData`
}

func defaultConfig() desktop.Config {
	images := `C:\Program Files\OpenDeploy\guest`
	if exe, err := os.Executable(); err == nil {
		images = filepath.Join(filepath.Dir(filepath.Dir(exe)), "guest")
	}
	return desktop.Config{ImageDir: images, DataDir: filepath.Join(programData(), "OpenDeploy")}
}

func newGuest(cfg desktop.Config, log *slog.Logger) (desktop.Guest, error) {
	wsl := filepath.Join(os.Getenv("SystemRoot"), "System32", "wsl.exe")
	if _, err := os.Stat(wsl); err != nil {
		wsl = "wsl.exe"
	}
	w := &desktop.WSL{Exe: wsl, Distro: distroName, InstallDir: filepath.Join(cfg.DataDir, "wsl"),
		Rootfs: filepath.Join(cfg.ImageDir, "opendeploy.wsl"), Log: log}
	// Only the service (running as its own account) owns a WSL VM to configure.
	if isSvc, _ := svc.IsWindowsService(); isSvc {
		if home, err := os.UserHomeDir(); err == nil {
			w.ConfigFile = filepath.Join(home, ".wslconfig")
		}
	}
	return w, nil
}

// ---- service main ---------------------------------------------------------------

type handler struct{ cfg desktop.Config }

func (h handler) Execute(_ []string, req <-chan svc.ChangeRequest, st chan<- svc.Status) (bool, uint32) {
	st <- svc.Status{State: svc.StartPending}
	log, closeLog := logger(h.cfg, false)
	defer closeLog()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- supervise(ctx, h.cfg, log) }()
	accepts := svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPreShutdown
	st <- svc.Status{State: svc.Running, Accepts: accepts}
	for {
		select {
		case err := <-done:
			if err != nil {
				log.Error("supervisor failed", "err", err)
				return true, 1
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				st <- c.CurrentStatus
			case svc.Stop, svc.Shutdown, svc.PreShutdown:
				cancel()
				// Keep the SCM informed while the guest shuts down.
				for checkpoint := uint32(1); ; checkpoint++ {
					st <- svc.Status{State: svc.StopPending, CheckPoint: checkpoint, WaitHint: 20000}
					select {
					case <-done:
						return false, 0
					case <-time.After(10 * time.Second):
					}
				}
			}
		}
	}
}

func run(cfg desktop.Config) error {
	isSvc, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	if isSvc {
		return svc.Run(serviceName, handler{cfg})
	}
	return runForeground(cfg, true)
}

// ---- install / uninstall ---------------------------------------------------------

var (
	netapi32            = windows.NewLazySystemDLL("netapi32.dll")
	procNetUserAdd      = netapi32.NewProc("NetUserAdd")
	procNetUserSet      = netapi32.NewProc("NetUserSetInfo")
	procNetUserDel      = netapi32.NewProc("NetUserDel")
	advapi32            = windows.NewLazySystemDLL("advapi32.dll")
	procLsaOpenPolicy   = advapi32.NewProc("LsaOpenPolicy")
	procLsaAddRights    = advapi32.NewProc("LsaAddAccountRights")
	procLsaRemoveRights = advapi32.NewProc("LsaRemoveAccountRights")
	procLsaClose        = advapi32.NewProc("LsaClose")
	procLsaNtToWin      = advapi32.NewProc("LsaNtStatusToWinError")
)

const (
	nerrUserExists           = 2224
	nerrUserNotFound         = 2221
	userPrivUser             = 1
	ufScript                 = 0x0001
	ufPasswdCantChange       = 0x0040
	ufDontExpirePasswd       = 0x10000
	policyCreateAccount      = 0x00000010
	policyLookupNames        = 0x00000800
	statusObjectNameNotFound = 0xC0000034 // LSA: the account holds no rights
	userListKey              = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList`
	passwordAlphabet         = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789-_.!#%+="
	passwordLength           = 40
	serviceRestartDelay      = 15 * time.Second
	serviceFailureResetSecs  = 24 * 60 * 60
)

type userInfo1 struct {
	Name        *uint16
	Password    *uint16
	PasswordAge uint32
	Priv        uint32
	HomeDir     *uint16
	Comment     *uint16
	Flags       uint32
	ScriptPath  *uint16
}

type userInfo1003 struct{ Password *uint16 }

func randomPassword() (string, error) {
	var b strings.Builder
	for i := 0; i < passwordLength; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(passwordAlphabet))))
		if err != nil {
			return "", err
		}
		b.WriteByte(passwordAlphabet[n.Int64()])
	}
	// Satisfy complexity policies regardless of the random draw.
	return b.String() + "aA7!", nil
}

// ensureAccount creates the service account (or resets its password when it
// already exists) and returns the password for the SCM.
func ensureAccount() (string, error) {
	pw, err := randomPassword()
	if err != nil {
		return "", err
	}
	name, _ := windows.UTF16PtrFromString(serviceAccount)
	pwp, _ := windows.UTF16PtrFromString(pw)
	comment, _ := windows.UTF16PtrFromString("OpenDeploy data plane service account")
	ui := userInfo1{Name: name, Password: pwp, Priv: userPrivUser, Comment: comment,
		Flags: ufScript | ufPasswdCantChange | ufDontExpirePasswd}
	var parmErr uint32
	r, _, _ := procNetUserAdd.Call(0, 1, uintptr(unsafe.Pointer(&ui)), uintptr(unsafe.Pointer(&parmErr)))
	switch r {
	case 0:
	case nerrUserExists:
		info := userInfo1003{Password: pwp}
		if r, _, _ := procNetUserSet.Call(0, uintptr(unsafe.Pointer(name)), 1003, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&parmErr))); r != 0 {
			return "", fmt.Errorf("reset password of %s: NetUserSetInfo error %d", serviceAccount, r)
		}
	default:
		return "", fmt.Errorf("create account %s: NetUserAdd error %d", serviceAccount, r)
	}
	if err := grantAccountRights(); err != nil {
		return "", err
	}
	// Hide it from the sign-in screen.
	if k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, userListKey, registry.SET_VALUE); err == nil {
		_ = k.SetDWordValue(serviceAccount, 0)
		k.Close()
	}
	return pw, nil
}

// serviceAccountRights are the service account's user rights: it may log on
// as a service and is denied every other logon type (at the console, over
// Remote Desktop, from the network, as a batch job), so the account cannot
// be used to sign in, even with its password.
func serviceAccountRights() []string {
	return []string{
		"SeServiceLogonRight",
		"SeDenyInteractiveLogonRight",
		"SeDenyRemoteInteractiveLogonRight",
		"SeDenyNetworkLogonRight",
		"SeDenyBatchLogonRight",
	}
}

// lsaStrings builds the LSA_UNICODE_STRING array that LsaAddAccountRights
// takes (a pointer to the first element and a count).
func lsaStrings(rights []string) ([]windows.NTUnicodeString, error) {
	out := make([]windows.NTUnicodeString, len(rights))
	for i, r := range rights {
		u, err := windows.NewNTUnicodeString(r)
		if err != nil {
			return nil, err
		}
		out[i] = *u
	}
	return out, nil
}

func openPolicy(access uintptr) (uintptr, error) {
	var attrs windows.OBJECT_ATTRIBUTES
	attrs.Length = uint32(unsafe.Sizeof(attrs))
	var policy uintptr
	if st, _, _ := procLsaOpenPolicy.Call(0, uintptr(unsafe.Pointer(&attrs)), access, uintptr(unsafe.Pointer(&policy))); st != 0 {
		return 0, fmt.Errorf("LsaOpenPolicy: %w", lsaError(st))
	}
	return policy, nil
}

// grantAccountRights gives the account serviceAccountRights. Adding rights
// the account already holds succeeds, so a reinstall is idempotent.
func grantAccountRights() error {
	sid, _, _, err := windows.LookupSID("", serviceAccount)
	if err != nil {
		return err
	}
	rights, err := lsaStrings(serviceAccountRights())
	if err != nil {
		return err
	}
	// Adding rights may create the account's LSA entry.
	policy, err := openPolicy(policyCreateAccount | policyLookupNames)
	if err != nil {
		return err
	}
	defer procLsaClose.Call(policy)
	st, _, _ := procLsaAddRights.Call(policy, uintptr(unsafe.Pointer(sid)), uintptr(unsafe.Pointer(&rights[0])), uintptr(len(rights)))
	runtime.KeepAlive(rights)
	if st != 0 {
		return fmt.Errorf("grant %s to %s: %w", strings.Join(serviceAccountRights(), ", "), serviceAccount, lsaError(st))
	}
	return nil
}

// removeAccountRights removes every user right of the account (AllRights),
// so no entry for its SID is left in the local security policy once the
// account is deleted. An account that is gone or holds no rights is fine.
func removeAccountRights() error {
	sid, _, _, err := windows.LookupSID("", serviceAccount)
	if errors.Is(err, windows.ERROR_NONE_MAPPED) {
		return nil
	}
	if err != nil {
		return err
	}
	// LsaRemoveAccountRights needs POLICY_LOOKUP_NAMES.
	policy, err := openPolicy(policyLookupNames)
	if err != nil {
		return err
	}
	defer procLsaClose.Call(policy)
	const allRights = 1
	if st, _, _ := procLsaRemoveRights.Call(policy, uintptr(unsafe.Pointer(sid)), allRights, 0, 0); st != 0 && st != statusObjectNameNotFound {
		return fmt.Errorf("remove the user rights of %s: %w", serviceAccount, lsaError(st))
	}
	return nil
}

func lsaError(st uintptr) error {
	code, _, _ := procLsaNtToWin.Call(st)
	return windows.Errno(code)
}

// secureDataDir restricts the data directory (WSL disk, status, bootstrap
// token) to SYSTEM, Administrators and the service account.
func secureDataDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	sid, _, _, err := windows.LookupSID("", serviceAccount)
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString(fmt.Sprintf("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;%s)", sid.String()))
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

func installService(cfg desktop.Config) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(cfg.ImageDir, "opendeploy.wsl")); err != nil {
		return fmt.Errorf("guest image missing: %w", err)
	}
	// Check the data folder before changing anything. resolveDataDir already
	// made it the existing node's folder, or refused a different one.
	def := defaultDataDir()
	home, err := existingHome(def)
	if err != nil {
		return err
	}
	ours := samePath(cfg.DataDir, home.Dir) || samePath(cfg.DataDir, def)
	if err := validateDataDir(cfg.DataDir, hostSystemDirs(), ours); err != nil {
		return fmt.Errorf("data folder: %w", err)
	}
	if err := volumeOf(cfg.DataDir); err != nil {
		return fmt.Errorf("data folder %s: %w", cfg.DataDir, err)
	}
	fmt.Printf("Node data folder: %s\n", cfg.DataDir)
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("%w (run from an elevated prompt)", err)
	}
	defer m.Disconnect()
	pw, err := ensureAccount()
	if err != nil {
		return err
	}
	if err := secureDataDir(cfg.DataDir); err != nil {
		return fmt.Errorf("secure %s: %w", cfg.DataDir, err)
	}
	if err := writeMarker(cfg.DataDir); err != nil {
		return fmt.Errorf("mark %s as the OpenDeploy data folder: %w", cfg.DataDir, err)
	}
	c := mgr.Config{
		DisplayName:      "OpenDeploy",
		Description:      "Runs the OpenDeploy data plane (managed WSL2 distribution) and serves the dashboard on http://127.0.0.1:8080.",
		StartType:        mgr.StartAutomatic,
		DelayedAutoStart: true,
		ServiceStartName: `.\` + serviceAccount,
		Password:         pw,
	}
	args := []string{"run", "--images", cfg.ImageDir, "--data", cfg.DataDir}
	s, err := m.OpenService(serviceName)
	if err == nil {
		// Upgrade: refresh binary path, account password and arguments. The
		// data folder is the service's own (resolveDataDir), so it is kept.
		defer s.Close()
		_, _ = s.Control(svc.Stop)
		waitState(s, svc.Stopped, time.Minute)
		cur, err := s.Config()
		if err != nil {
			return err
		}
		cur.BinaryPathName = quoteArgs(append([]string{exe}, args...))
		cur.ServiceStartName, cur.Password = c.ServiceStartName, c.Password
		cur.DisplayName, cur.Description, cur.StartType, cur.DelayedAutoStart = c.DisplayName, c.Description, c.StartType, true
		if err := s.UpdateConfig(cur); err != nil {
			return err
		}
	} else {
		s, err = m.CreateService(serviceName, exe, c, args...)
		if err != nil {
			return err
		}
		defer s.Close()
	}
	actions := []mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: serviceRestartDelay}, {Type: mgr.ServiceRestart, Delay: serviceRestartDelay}, {Type: mgr.ServiceRestart, Delay: time.Minute}}
	if err := s.SetRecoveryActions(actions, serviceFailureResetSecs); err != nil {
		return err
	}
	// Remembered for a reinstall after an uninstall that keeps the data.
	if err := recordDataDir(cfg.DataDir); err != nil {
		return fmt.Errorf(`record the data folder in HKLM\%s: %w`, dataRegKey, err)
	}
	if err := s.Start(); err != nil {
		return err
	}
	fmt.Println("OpenDeploy service installed and started. The first start imports the WSL distribution and can")
	fmt.Println("take a few minutes; check progress with: opendeploy-desktop status (as administrator)")
	return nil
}

func quoteArgs(args []string) string {
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = windows.EscapeArg(a)
	}
	return strings.Join(q, " ")
}

func waitState(s *mgr.Service, want svc.State, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if st, err := s.Query(); err != nil || st.State == want {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func uninstallService(cfg desktop.Config, purge bool) error {
	def, sys := defaultDataDir(), hostSystemDirs()
	if purge {
		// Refuse before removing anything if the folder is not ours to delete.
		if err := checkPurge(cfg.DataDir, def, sys); err != nil {
			return err
		}
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("%w (run from an elevated prompt)", err)
	}
	defer m.Disconnect()
	if s, err := m.OpenService(serviceName); err == nil {
		_, _ = s.Control(svc.Stop)
		waitState(s, svc.Stopped, 2*time.Minute)
		err = s.Delete()
		s.Close()
		if err != nil {
			return err
		}
	}
	if !purge {
		fmt.Printf("Service removed. The node's data is kept in %s (uninstall --purge deletes it).\n", cfg.DataDir)
		return nil
	}
	// The distro is registered to the service account; deleting the account
	// and the directory holding ext4.vhdx removes the node entirely. Its
	// rights go first: the policy keeps them by SID after the account is gone.
	if err := removeAccountRights(); err != nil {
		return err
	}
	name, _ := windows.UTF16PtrFromString(serviceAccount)
	if r, _, _ := procNetUserDel.Call(0, uintptr(unsafe.Pointer(name))); r != 0 && r != nerrUserNotFound {
		return fmt.Errorf("delete account %s: NetUserDel error %d", serviceAccount, r)
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, userListKey, registry.SET_VALUE); err == nil {
		_ = k.DeleteValue(serviceAccount)
		k.Close()
	}
	if err := purgeDataDir(cfg.DataDir, def, sys); err != nil {
		return err
	}
	forgetDataDir()
	fmt.Printf("Removed the OpenDeploy service, its account and all node data (%s).\n", cfg.DataDir)
	return nil
}

func control(cmd svc.Cmd, want svc.State) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return errors.New("the OpenDeploy service is not installed")
	}
	defer s.Close()
	if cmd == 0 {
		err = s.Start()
	} else {
		_, err = s.Control(cmd)
	}
	if err != nil {
		return err
	}
	waitState(s, want, 3*time.Minute)
	return nil
}

func startService() error { return control(0, svc.Running) }
func stopService() error  { return control(svc.Stop, svc.Stopped) }
