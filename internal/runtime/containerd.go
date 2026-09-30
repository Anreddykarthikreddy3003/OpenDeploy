package runtime

import (
	"errors"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/config"
)

// NewContainerd returns the containerd backend (set by containerd_linux.go
// on Linux; the data plane always runs in a Linux host or guest).
var NewContainerd = func(c config.RuntimeConfig, secretsDir string) (Backend, error) {
	return nil, errors.New("the containerd backend is only available on Linux")
}
