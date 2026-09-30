//go:build linux

package ipc

import (
	"net"

	"golang.org/x/sys/unix"
)

// peerCred returns the kernel-verified credentials of a Unix socket peer.
func peerCred(c net.Conn) (Peer, bool) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return Peer{}, false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return Peer{}, false
	}
	var cred *unix.Ucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		cred, serr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil || serr != nil || cred == nil {
		return Peer{}, false
	}
	return Peer{UID: cred.Uid, GID: cred.Gid, PID: cred.Pid, Verified: true}, true
}
