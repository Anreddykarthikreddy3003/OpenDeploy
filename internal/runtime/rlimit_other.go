//go:build !unix

package runtime

func hostNoFile() int64 { return 65536 }
