//go:build !linux

package ipc

import "net"

// peerCred is unavailable off Linux; the data plane always runs in the Linux
// guest, so host-side IPC relies on socket file permissions only.
func peerCred(c net.Conn) (Peer, bool) { return Peer{}, false }
