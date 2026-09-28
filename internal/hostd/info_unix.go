//go:build unix

package hostd

import "golang.org/x/sys/unix"

func kernelRelease() string {
	var u unix.Utsname
	if unix.Uname(&u) != nil {
		return ""
	}
	return unix.ByteSliceToString(u.Release[:])
}

func diskFree(dir string) uint64 {
	var st unix.Statfs_t
	if unix.Statfs(dir, &st) != nil {
		return 0
	}
	return st.Bavail * uint64(st.Bsize)
}
