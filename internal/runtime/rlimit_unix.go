//go:build unix

package runtime

import "syscall"

// hostNoFile returns min(65536, host hard RLIMIT_NOFILE) so containers never
// request more than the engine is permitted to grant.
func hostNoFile() int64 {
	var r syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &r); err != nil || r.Max == 0 {
		return 1024
	}
	if r.Max > 65536 {
		return 65536
	}
	return int64(r.Max)
}
