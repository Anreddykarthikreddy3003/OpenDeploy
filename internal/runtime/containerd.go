package runtime

import (
	"errors"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/config"
)

// NewContainerd returns the containerd backend. It is implemented together
// with egressd's netns/veth plumbing (see containerd_linux.go when present).
var NewContainerd = func(c config.RuntimeConfig, secretsDir string) (Backend, error) {
	return nil, errors.New("containerd backend is not available in this build; set runtime.backend: docker")
}
