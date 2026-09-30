package desktop

import (
	"os/exec"
	"syscall"
)

const createNoWindow = 0x08000000

func init() {
	hideConsole = func(c *exec.Cmd) {
		c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	}
}
