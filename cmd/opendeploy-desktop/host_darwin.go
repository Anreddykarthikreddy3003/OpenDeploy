package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/desktop"
)

// launchd job for the host service. It runs as root so it can bind the edge
// ports 80/443 on the loopback; the VM itself holds all OpenDeploy state.
const (
	launchdLabel = "io.github.anreddykarthikreddy3003.opendeploy.desktop"
	launchdPlist = "/Library/LaunchDaemons/" + launchdLabel + ".plist"
	installRoot  = "/Library/OpenDeploy"
	logDir       = "/Library/Logs/OpenDeploy"
)

func defaultConfig() desktop.Config {
	return desktop.Config{
		ImageDir: filepath.Join(installRoot, "guest"),
		DataDir:  "/Library/Application Support/OpenDeploy",
	}
}

func newGuest(cfg desktop.Config, log *slog.Logger) (desktop.Guest, error) {
	return &desktop.VZ{Config: cfg, Log: log}, nil
}

func run(cfg desktop.Config) error { return runForeground(cfg, isTerminal()) }

func isTerminal() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

var plistTmpl = template.Must(template.New("plist").Parse(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{{.Label}}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{{.Exe}}</string>
		<string>run</string>
		<string>--images</string>
		<string>{{.Cfg.ImageDir}}</string>
		<string>--data</string>
		<string>{{.Cfg.DataDir}}</string>
		<string>--cpus</string>
		<string>{{.Cfg.CPUs}}</string>
		<string>--memory</string>
		<string>{{.Cfg.MemoryMiB}}</string>
		<string>--disk</string>
		<string>{{.Cfg.DiskGiB}}</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ProcessType</key>
	<string>Standard</string>
	<key>ExitTimeOut</key>
	<integer>120</integer>
	<key>StandardOutPath</key>
	<string>{{.LogDir}}/desktop.out.log</string>
	<key>StandardErrorPath</key>
	<string>{{.LogDir}}/desktop.err.log</string>
</dict>
</plist>
`))

func launchctl(args ...string) error {
	out, err := exec.Command("/bin/launchctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func installService(cfg desktop.Config) error {
	if os.Geteuid() != 0 {
		return errors.New("run with sudo")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	for _, d := range []string{cfg.DataDir, logDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(launchdPlist+".tmp", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	err = plistTmpl.Execute(f, map[string]any{"Label": launchdLabel, "Exe": exe, "Cfg": cfg, "LogDir": logDir})
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(launchdPlist+".tmp", launchdPlist); err != nil {
		return err
	}
	_ = launchctl("bootout", "system/"+launchdLabel) // reinstall/upgrade
	if err := launchctl("bootstrap", "system", launchdPlist); err != nil {
		return err
	}
	fmt.Println("OpenDeploy service installed. The first start creates the VM disk and can take a few minutes;")
	fmt.Println("check progress with: sudo opendeploy-desktop status")
	return nil
}

func uninstallService(cfg desktop.Config, purge bool) error {
	if os.Geteuid() != 0 {
		return errors.New("run with sudo")
	}
	_ = launchctl("bootout", "system/"+launchdLabel)
	if err := os.Remove(launchdPlist); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if purge {
		if err := os.RemoveAll(cfg.DataDir); err != nil {
			return err
		}
		fmt.Println("Removed the OpenDeploy VM and all of its data.")
	} else {
		fmt.Printf("Service removed. The node's data is kept in %s (uninstall --purge deletes it).\n", cfg.DataDir)
	}
	return nil
}

func startService() error {
	if launchctl("print", "system/"+launchdLabel) != nil { // unloaded by `stop`
		return launchctl("bootstrap", "system", launchdPlist)
	}
	return launchctl("kickstart", "system/"+launchdLabel)
}

func stopService() error {
	// KeepAlive would restart a killed job: stop by unloading it until the
	// next `start`/boot.
	return launchctl("bootout", "system/"+launchdLabel)
}
