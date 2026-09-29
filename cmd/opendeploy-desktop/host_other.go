//go:build !windows && !darwin

package main

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/desktop"
)

var errLinux = errors.New("on Linux, OpenDeploy runs natively: install the opendeploy deb/rpm package instead")

func defaultConfig() desktop.Config {
	return desktop.Config{ImageDir: "/usr/lib/opendeploy/guest", DataDir: filepath.Join(os.TempDir(), "opendeploy-desktop")}
}

func newGuest(desktop.Config, *slog.Logger) (desktop.Guest, error) { return nil, errLinux }
func run(desktop.Config) error                                     { return errLinux }
func installService(desktop.Config) error                          { return errLinux }
func uninstallService(desktop.Config, bool) error                  { return errLinux }
func startService() error                                          { return errLinux }
func stopService() error                                           { return errLinux }
