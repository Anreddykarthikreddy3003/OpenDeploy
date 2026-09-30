package runtime

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Backend is a container runtime implementation.
type Backend interface {
	Name() string
	Capabilities(ctx context.Context) (*Capabilities, error)
	EnsureNetwork(ctx context.Context, n NetworkSpec) (*NetworkInfo, error)
	RemoveNetwork(ctx context.Context, envID string) error
	Start(ctx context.Context, s *Spec, auth RegistryAuth) (*Workload, error)
	Stop(ctx context.Context, id string, timeout time.Duration) error
	Remove(ctx context.Context, id string) error
	Inspect(ctx context.Context, id string) (*Workload, error)
	List(ctx context.Context, filter map[string]string) ([]Workload, error)
	Logs(ctx context.Context, id string, tail int, since time.Time) ([]LogLine, error)
}

// RegistryAuth holds pull credentials for artifactd's registry.
type RegistryAuth struct {
	Server   string
	User     string
	Password string
}

// LogLine is one line of workload output (untrusted content).
type LogLine struct {
	Time   string `json:"time"`
	Stream string `json:"stream"`
	Text   string `json:"text"`
}

// ErrNotFound means the workload does not exist.
var ErrNotFound = errors.New("workload not found")

// Docker implements Backend against the Docker Engine API.
type Docker struct {
	hc         *http.Client
	SecretsDir string // host tmpfs dir for secret files
	VolumesDir string
	Runsc      string // docker runtime name for gVisor ("runsc")

	verMu  sync.Mutex
	apiVer apiVersion // negotiated with the engine on first use; zero until then
}

// The Engine API versions this client speaks. Every request body and every
// response field docker.go uses was checked against the Engine API version
// history for each version in this range, so each of them means the same
// thing at any version in it. 1.43 is Docker 24 (the version this client was
// written against); 1.52 is Docker 29. Raise the maximum only after
// repeating that check for the new versions.
var (
	dockerMinAPIVersion = apiVersion{1, 43}
	dockerMaxAPIVersion = apiVersion{1, 52}
)

// apiVersion is a Docker Engine API version ("1.52").
type apiVersion struct{ major, minor int }

func (v apiVersion) String() string { return fmt.Sprintf("%d.%d", v.major, v.minor) }

func (v apiVersion) less(o apiVersion) bool {
	return v.major < o.major || (v.major == o.major && v.minor < o.minor)
}

func parseAPIVersion(s string) (apiVersion, bool) {
	a, b, ok := strings.Cut(s, ".")
	if !ok {
		return apiVersion{}, false
	}
	major, err1 := strconv.Atoi(a)
	minor, err2 := strconv.Atoi(b)
	if err1 != nil || err2 != nil || major < 1 || minor < 0 {
		return apiVersion{}, false
	}
	return apiVersion{major, minor}, true
}

// negotiateAPIVersion picks the API version to use with an engine that
// reports ApiVersion server and MinAPIVersion serverMin in GET /version, the
// way the Docker CLI does: the lower of the engine's version and the
// client's maximum, provided the engine still accepts it.
func negotiateAPIVersion(server, serverMin string) (apiVersion, error) {
	sv, ok := parseAPIVersion(server)
	if !ok {
		return apiVersion{}, fmt.Errorf("docker: engine reported an invalid API version %q", server)
	}
	v := sv
	if dockerMaxAPIVersion.less(v) {
		v = dockerMaxAPIVersion
	}
	if serverMin != "" {
		mv, ok := parseAPIVersion(serverMin)
		if !ok {
			return apiVersion{}, fmt.Errorf("docker: engine reported an invalid minimum API version %q", serverMin)
		}
		if v.less(mv) {
			return apiVersion{}, fmt.Errorf("docker: engine requires API version %s or newer, but OpenDeploy supports at most %s; use an older Docker Engine or a newer OpenDeploy", mv, dockerMaxAPIVersion)
		}
	}
	if v.less(dockerMinAPIVersion) {
		return apiVersion{}, fmt.Errorf("docker: engine API version %s is older than %s, the oldest OpenDeploy supports; upgrade Docker Engine to 24.0 or newer", sv, dockerMinAPIVersion)
	}
	return v, nil
}

// apiVersion returns the negotiated API version, asking the engine once per
// client. A failed negotiation is not cached, so an engine that was not up
// yet is asked again on the next request.
func (d *Docker) apiVersion(ctx context.Context) (apiVersion, error) {
	d.verMu.Lock()
	defer d.verMu.Unlock()
	if d.apiVer != (apiVersion{}) {
		return d.apiVer, nil
	}
	// GET /version is served unversioned by every engine.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/version", nil)
	if err != nil {
		return apiVersion{}, err
	}
	resp, err := d.hc.Do(req)
	if err != nil {
		return apiVersion{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return apiVersion{}, readAPIError(resp)
	}
	var info struct {
		APIVersion    string `json:"ApiVersion"`
		MinAPIVersion string `json:"MinAPIVersion"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&info); err != nil {
		return apiVersion{}, fmt.Errorf("docker: GET /version: %w", err)
	}
	v, err := negotiateAPIVersion(info.APIVersion, info.MinAPIVersion)
	if err != nil {
		return apiVersion{}, err
	}
	d.apiVer = v
	return v, nil
}

// NewDocker connects to a Docker Engine socket (unix:///var/run/docker.sock).
func NewDocker(host, secretsDir, volumesDir string) (*Docker, error) {
	u, err := url.Parse(host)
	if err != nil || u.Scheme != "unix" {
		return nil, fmt.Errorf("docker host must be unix://")
	}
	sock := u.Path
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock)
	}}
	return &Docker{hc: &http.Client{Transport: tr}, SecretsDir: secretsDir, VolumesDir: volumesDir, Runsc: "runsc"}, nil
}

func (d *Docker) Name() string { return "docker" }

type apiError struct {
	Status  int
	Message string
}

func (e *apiError) Error() string { return fmt.Sprintf("docker: %d %s", e.Status, e.Message) }

// do sends one request to the engine at the negotiated API version; every
// Engine API request goes through here. A non-2xx response is returned as an
// *apiError; otherwise the caller closes the body.
func (d *Docker) do(ctx context.Context, method, p string, q url.Values, body io.Reader, hdr http.Header) (*http.Response, error) {
	ver, err := d.apiVersion(ctx)
	if err != nil {
		return nil, err
	}
	u := "http://docker/v" + ver.String() + p
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	resp, err := d.hc.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		defer resp.Body.Close()
		return nil, readAPIError(resp)
	}
	return resp, nil
}

func readAPIError(resp *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	var m struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(b, &m)
	if m.Message == "" {
		m.Message = strings.TrimSpace(string(b))
	}
	return &apiError{Status: resp.StatusCode, Message: m.Message}
}

func (d *Docker) call(ctx context.Context, method, p string, q url.Values, body any, hdr http.Header, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
		if hdr = hdr.Clone(); hdr == nil {
			hdr = http.Header{}
		}
		hdr.Set("Content-Type", "application/json")
	}
	resp, err := d.do(ctx, method, p, q, rdr, hdr)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(out)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

func isNotFound(err error) bool {
	var ae *apiError
	return errors.As(err, &ae) && ae.Status == 404
}

// Capabilities probes the engine.
func (d *Docker) Capabilities(ctx context.Context) (*Capabilities, error) {
	var info struct {
		ServerVersion string                     `json:"ServerVersion"`
		Runtimes      map[string]json.RawMessage `json:"Runtimes"`
	}
	if err := d.call(ctx, http.MethodGet, "/info", nil, nil, nil, &info); err != nil {
		return nil, err
	}
	c := &Capabilities{Backend: "docker", Version: info.ServerVersion, Runtimes: map[string]bool{RuntimeRunc: true}, Devices: map[string]bool{}}
	if _, ok := info.Runtimes[d.Runsc]; ok {
		c.Runtimes[RuntimeRunsc] = true
	}
	for _, vm := range []string{"kata", "kata-runtime", "io.containerd.kata.v2"} {
		if _, ok := info.Runtimes[vm]; ok {
			c.Runtimes[RuntimeVM] = true
		}
	}
	if _, err := os.Stat("/dev/kvm"); err == nil {
		c.Devices["kvm"] = true
	}
	if _, err := os.Stat("/dev/fuse"); err == nil {
		c.Devices["fuse"] = true
	}
	if _, err := os.Stat("/dev/nvidiactl"); err == nil {
		c.Devices["gpu"] = true
	}
	return c, nil
}

// EnsureNetwork creates the per-environment bridge network. Docker isolates
// user-defined bridges from each other; egressd adds host/LAN deny rules.
func (d *Docker) EnsureNetwork(ctx context.Context, n NetworkSpec) (*NetworkInfo, error) {
	name := NetworkName(n.EnvironmentID)
	info, err := d.inspectNetwork(ctx, name)
	if err == nil {
		return info, nil
	}
	if !isNotFound(err) {
		return nil, err
	}
	ver, err := d.apiVersion(ctx)
	if err != nil {
		return nil, err
	}
	body := map[string]any{
		"Name":       name,
		"Driver":     "bridge",
		"Internal":   false,
		"EnableIPv6": false,
		"Options": map[string]string{
			"com.docker.network.bridge.enable_icc":           "true",
			"com.docker.network.bridge.enable_ip_masquerade": "true",
			"com.docker.network.bridge.name":                 bridgeName(n.EnvironmentID),
		},
		"Labels": map[string]string{"org.opendeploy.managed": "true", "org.opendeploy.environment": n.EnvironmentID,
			"org.opendeploy.project": n.ProjectID, "org.opendeploy.kind": n.Kind},
	}
	if ver.less(apiVersion{1, 44}) {
		// From 1.44 an engine always refuses a duplicate name and the
		// field is deprecated; before that the check must be asked for.
		body["CheckDuplicate"] = true
	}
	if err := d.call(ctx, http.MethodPost, "/networks/create", nil, body, nil, nil); err != nil {
		var ae *apiError
		if !(errors.As(err, &ae) && ae.Status == 409) {
			return nil, err
		}
	}
	return d.inspectNetwork(ctx, name)
}

// bridgeName is a deterministic <=15 char interface name for nftables rules.
func bridgeName(envID string) string {
	s := strings.TrimPrefix(envID, "env_")
	if len(s) > 11 {
		s = s[:11]
	}
	return "od" + s
}

func (d *Docker) inspectNetwork(ctx context.Context, name string) (*NetworkInfo, error) {
	var n struct {
		ID   string `json:"Id"`
		Name string `json:"Name"`
		IPAM struct {
			Config []struct {
				Subnet  string `json:"Subnet"`
				Gateway string `json:"Gateway"`
			} `json:"Config"`
		} `json:"IPAM"`
		Options map[string]string `json:"Options"`
	}
	if err := d.call(ctx, http.MethodGet, "/networks/"+url.PathEscape(name), nil, nil, nil, &n); err != nil {
		return nil, err
	}
	out := &NetworkInfo{ID: n.ID, Name: n.Name, Bridge: n.Options["com.docker.network.bridge.name"]}
	if len(n.IPAM.Config) > 0 {
		out.Subnet, out.Gateway = n.IPAM.Config[0].Subnet, n.IPAM.Config[0].Gateway
	}
	return out, nil
}

func (d *Docker) RemoveNetwork(ctx context.Context, envID string) error {
	err := d.call(ctx, http.MethodDelete, "/networks/"+url.PathEscape(NetworkName(envID)), nil, nil, nil, nil)
	if isNotFound(err) {
		return nil
	}
	return err
}

func containerName(id string) string { return "od-" + strings.ReplaceAll(id, "_", "-") }

func (d *Docker) pull(ctx context.Context, image string, auth RegistryAuth) error {
	ref, tag := image, ""
	if i := strings.Index(image, "@"); i > 0 {
		ref, tag = image[:i], image[i+1:]
	} else if i := strings.LastIndex(image, ":"); i > strings.LastIndex(image, "/") {
		ref, tag = image[:i], image[i+1:]
	}
	q := url.Values{"fromImage": {ref}}
	if tag != "" {
		q.Set("tag", tag)
	}
	hdr := http.Header{}
	if auth.Server != "" && strings.HasPrefix(image, auth.Server+"/") {
		a, _ := json.Marshal(map[string]string{"username": auth.User, "password": auth.Password, "serveraddress": auth.Server})
		hdr.Set("X-Registry-Auth", base64.URLEncoding.EncodeToString(a))
	}
	// The pull endpoint streams JSON progress; errors appear in-stream.
	resp, err := d.do(ctx, http.MethodPost, "/images/create", q, nil, hdr)
	if err != nil {
		return fmt.Errorf("pull %s: %w", image, err)
	}
	defer resp.Body.Close()
	dec := json.NewDecoder(resp.Body)
	for {
		// "error" is deprecated since API 1.48 and may be left empty by
		// newer engines; "errorDetail" carries the same message.
		var m struct {
			Error       string `json:"error"`
			ErrorDetail struct {
				Message string `json:"message"`
			} `json:"errorDetail"`
		}
		if err := dec.Decode(&m); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if msg := m.ErrorDetail.Message; msg != "" {
			return fmt.Errorf("pull %s: %s", image, msg)
		}
		if m.Error != "" {
			return fmt.Errorf("pull %s: %s", image, m.Error)
		}
	}
}

// Start creates and starts a hardened container.
func (d *Docker) Start(ctx context.Context, s *Spec, auth RegistryAuth) (*Workload, error) {
	name := containerName(s.ID)
	if w, err := d.Inspect(ctx, s.ID); err == nil {
		if w.State == "running" {
			return w, nil
		}
		if err := d.call(ctx, http.MethodPost, "/containers/"+name+"/start", nil, nil, nil, nil); err != nil {
			return nil, err
		}
		return d.Inspect(ctx, s.ID)
	}
	if err := d.pull(ctx, s.Image, auth); err != nil {
		return nil, err
	}
	env := make([]string, 0, len(s.Env)+2)
	for k, v := range s.Env {
		env = append(env, k+"="+v)
	}
	if s.Port > 0 {
		env = append(env, "PORT="+strconv.Itoa(s.Port))
	}
	tmpfs := map[string]string{"/tmp": "rw,noexec,nosuid,nodev,size=256m"}
	for _, t := range s.Tmpfs {
		tmpfs[t] = "rw,nosuid,nodev,size=256m,mode=1777"
	}
	var mounts []map[string]any
	if len(s.SecretFiles) > 0 {
		dir, err := d.writeSecrets(s)
		if err != nil {
			return nil, err
		}
		mounts = append(mounts, map[string]any{"Type": "bind", "Source": dir, "Target": "/run/secrets", "ReadOnly": true,
			"BindOptions": map[string]any{"Propagation": "rprivate"}})
	}
	for _, v := range s.Volumes {
		src, err := d.volumePath(v)
		if err != nil {
			return nil, err
		}
		mounts = append(mounts, map[string]any{"Type": "bind", "Source": src, "Target": v.Target, "ReadOnly": v.ReadOnly,
			"BindOptions": map[string]any{"Propagation": "rprivate"}})
	}
	runtimeName := "runc"
	switch s.Runtime {
	case RuntimeRunsc:
		runtimeName = d.Runsc
	case RuntimeVM:
		runtimeName = "kata"
	}
	host := map[string]any{
		"NetworkMode":     NetworkName(s.EnvironmentID),
		"ReadonlyRootfs":  s.ReadOnlyRoot,
		"Tmpfs":           tmpfs,
		"CapDrop":         []string{"ALL"},
		"SecurityOpt":     []string{"no-new-privileges:true"},
		"Memory":          s.MemoryBytes,
		"MemorySwap":      s.MemoryBytes,
		"NanoCpus":        int64(s.CPU * 1e9),
		"PidsLimit":       s.PIDs,
		"Ulimits":         []map[string]any{{"Name": "nofile", "Soft": hostNoFile(), "Hard": hostNoFile()}},
		"Runtime":         runtimeName,
		"RestartPolicy":   map[string]any{"Name": "on-failure", "MaximumRetryCount": 5},
		"Init":            true,
		"Mounts":          mounts,
		"Privileged":      false,
		"PublishAllPorts": false,
		"IpcMode":         "private",
		"PidMode":         "",
		"LogConfig":       map[string]any{"Type": "json-file", "Config": map[string]string{"max-size": "10m", "max-file": "3"}},
		"ShmSize":         64 << 20,
	}
	if s.Kind == "backing" {
		// Official database images start as root to chown their data dir and
		// then drop to their service user; grant only what that needs.
		host["CapAdd"] = []string{"CHOWN", "SETUID", "SETGID", "DAC_OVERRIDE", "FOWNER"}
	}
	for _, c := range s.Capabilities {
		switch c {
		case "gpu":
			host["DeviceRequests"] = []map[string]any{{"Driver": "nvidia", "Count": -1, "Capabilities": [][]string{{"gpu"}}}}
		case "kvm":
			host["Devices"] = append(devList(host), map[string]string{"PathOnHost": "/dev/kvm", "PathInContainer": "/dev/kvm", "CgroupPermissions": "rw"})
		case "fuse":
			host["Devices"] = append(devList(host), map[string]string{"PathOnHost": "/dev/fuse", "PathInContainer": "/dev/fuse", "CgroupPermissions": "rw"})
			host["CapAdd"] = append(capList(host), "SYS_ADMIN")
		case "host-network":
			host["NetworkMode"] = "host"
		case "usb":
			return nil, fmt.Errorf("usb passthrough is not supported by the docker backend")
		}
	}
	body := map[string]any{
		"Image":      s.Image,
		"Env":        env,
		"Labels":     s.Labels(),
		"HostConfig": host,
		"StopSignal": "SIGTERM",
	}
	if s.User != "" {
		body["User"] = s.User
	}
	if len(s.Command) > 0 {
		body["Cmd"] = s.Command
	}
	if s.Port > 0 {
		body["ExposedPorts"] = map[string]any{fmt.Sprintf("%d/tcp", s.Port): map[string]any{}}
	}
	if host["NetworkMode"] != "host" {
		aliases := append([]string{s.Service}, s.Aliases...)
		body["NetworkingConfig"] = map[string]any{"EndpointsConfig": map[string]any{
			NetworkName(s.EnvironmentID): map[string]any{"Aliases": aliases},
		}}
	}
	var created struct {
		ID string `json:"Id"`
	}
	if err := d.call(ctx, http.MethodPost, "/containers/create", url.Values{"name": {name}}, body, nil, &created); err != nil {
		return nil, err
	}
	if err := d.call(ctx, http.MethodPost, "/containers/"+created.ID+"/start", nil, nil, nil, nil); err != nil {
		_ = d.call(ctx, http.MethodDelete, "/containers/"+created.ID, url.Values{"force": {"1"}}, nil, nil, nil)
		return nil, err
	}
	return d.Inspect(ctx, s.ID)
}

func devList(h map[string]any) []map[string]string {
	if v, ok := h["Devices"].([]map[string]string); ok {
		return v
	}
	return nil
}

func capList(h map[string]any) []string {
	if v, ok := h["CapAdd"].([]string); ok {
		return v
	}
	return nil
}

func (d *Docker) writeSecrets(s *Spec) (string, error) {
	dir := filepath.Join(d.SecretsDir, s.ID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	for name, val := range s.SecretFiles {
		p := filepath.Join(dir, name)
		tmp := p + ".tmp"
		if err := os.WriteFile(tmp, []byte(val), 0o444); err != nil {
			return "", err
		}
		if err := os.Rename(tmp, p); err != nil {
			return "", err
		}
	}
	return dir, nil
}

func (d *Docker) volumePath(v VolumeMount) (string, error) {
	p := filepath.Join(d.VolumesDir, v.VolumeID)
	if filepath.Dir(p) != filepath.Clean(d.VolumesDir) {
		return "", fmt.Errorf("invalid volume id")
	}
	if err := os.MkdirAll(p, 0o750); err != nil {
		return "", err
	}
	uid := v.OwnerUID
	if uid == 0 {
		uid = 10001
	}
	if uid > 0 {
		_ = os.Chown(p, uid, uid)
	}
	return p, nil
}

type inspect struct {
	ID    string `json:"Id"`
	State struct {
		Status    string `json:"Status"`
		Running   bool   `json:"Running"`
		ExitCode  int    `json:"ExitCode"`
		StartedAt string `json:"StartedAt"`
		OOMKilled bool   `json:"OOMKilled"`
	} `json:"State"`
	RestartCount int `json:"RestartCount"`
	Config       struct {
		Labels       map[string]string   `json:"Labels"`
		ExposedPorts map[string]struct{} `json:"ExposedPorts"`
	} `json:"Config"`
	NetworkSettings struct {
		Networks map[string]struct {
			IPAddress string `json:"IPAddress"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
}

func toWorkload(in inspect) *Workload {
	w := &Workload{ID: in.Config.Labels["org.opendeploy.workload"], RuntimeID: in.ID, ExitCode: in.State.ExitCode, StartedAt: in.State.StartedAt,
		Restarts: in.RestartCount, OOMKilled: in.State.OOMKilled, Labels: in.Config.Labels}
	switch {
	case in.State.Running:
		w.State = "running"
	case in.State.Status == "created":
		w.State = "created"
	default:
		w.State = "exited"
	}
	env := in.Config.Labels["org.opendeploy.environment"]
	if n, ok := in.NetworkSettings.Networks[NetworkName(env)]; ok {
		w.IP = n.IPAddress
	}
	port := 0
	for p := range in.Config.ExposedPorts {
		if n, err := strconv.Atoi(strings.TrimSuffix(p, "/tcp")); err == nil {
			port = n
		}
	}
	if w.IP != "" && port > 0 {
		w.Endpoint = net.JoinHostPort(w.IP, strconv.Itoa(port))
	}
	return w
}

func (d *Docker) Inspect(ctx context.Context, id string) (*Workload, error) {
	var in inspect
	if err := d.call(ctx, http.MethodGet, "/containers/"+containerName(id)+"/json", nil, nil, nil, &in); err != nil {
		if isNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if in.Config.Labels["org.opendeploy.managed"] != "true" {
		return nil, ErrNotFound
	}
	return toWorkload(in), nil
}

func (d *Docker) Stop(ctx context.Context, id string, timeout time.Duration) error {
	err := d.call(ctx, http.MethodPost, "/containers/"+containerName(id)+"/stop", url.Values{"t": {strconv.Itoa(int(timeout.Seconds()))}}, nil, nil, nil)
	if isNotFound(err) {
		return nil
	}
	var ae *apiError
	if errors.As(err, &ae) && ae.Status == 304 {
		return nil
	}
	return err
}

func (d *Docker) Remove(ctx context.Context, id string) error {
	err := d.call(ctx, http.MethodDelete, "/containers/"+containerName(id), url.Values{"force": {"1"}, "v": {"0"}}, nil, nil, nil)
	if isNotFound(err) {
		err = nil
	}
	_ = os.RemoveAll(filepath.Join(d.SecretsDir, id))
	return err
}

func (d *Docker) List(ctx context.Context, filter map[string]string) ([]Workload, error) {
	labels := []string{"org.opendeploy.managed=true"}
	for k, v := range filter {
		labels = append(labels, "org.opendeploy."+k+"="+v)
	}
	f, _ := json.Marshal(map[string][]string{"label": labels})
	var list []struct {
		ID string `json:"Id"`
	}
	if err := d.call(ctx, http.MethodGet, "/containers/json", url.Values{"all": {"1"}, "filters": {string(f)}}, nil, nil, &list); err != nil {
		return nil, err
	}
	out := make([]Workload, 0, len(list))
	for _, c := range list {
		var in inspect
		if err := d.call(ctx, http.MethodGet, "/containers/"+c.ID+"/json", nil, nil, nil, &in); err != nil {
			continue
		}
		out = append(out, *toWorkload(in))
	}
	return out, nil
}

// Logs returns demultiplexed container output.
func (d *Docker) Logs(ctx context.Context, id string, tail int, since time.Time) ([]LogLine, error) {
	if tail <= 0 || tail > 5000 {
		tail = 500
	}
	q := url.Values{"stdout": {"1"}, "stderr": {"1"}, "timestamps": {"1"}, "tail": {strconv.Itoa(tail)}}
	if !since.IsZero() {
		q.Set("since", strconv.FormatInt(since.Unix(), 10))
	}
	resp, err := d.do(ctx, http.MethodGet, "/containers/"+containerName(id)+"/logs", q, nil, nil)
	if isNotFound(err) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("logs: %w", err)
	}
	defer resp.Body.Close()
	var out []LogLine
	r := bufio.NewReader(io.LimitReader(resp.Body, 16<<20))
	hdr := make([]byte, 8)
	for {
		if _, err := io.ReadFull(r, hdr); err != nil {
			break
		}
		size := binary.BigEndian.Uint32(hdr[4:])
		if size > 1<<20 {
			break
		}
		buf := make([]byte, size)
		if _, err := io.ReadFull(r, buf); err != nil {
			break
		}
		stream := "stdout"
		if hdr[0] == 2 {
			stream = "stderr"
		}
		for _, line := range strings.Split(strings.TrimRight(string(buf), "\n"), "\n") {
			ts, text, _ := strings.Cut(line, " ")
			out = append(out, LogLine{Time: ts, Stream: stream, Text: text})
		}
	}
	return out, nil
}
