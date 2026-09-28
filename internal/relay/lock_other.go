//go:build !unix

package relay

// lockFile is process-local on platforms without flock (the relay server is
// supported on Linux; other builds are for development only).
func lockFile(string) (func(), error) { return func() {}, nil }
