package runtime

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeEngine is a Docker Engine API server that enforces API versions the
// way dockerd does: GET /version is unversioned, and a versioned request
// outside [min, api] gets the engine's own 400 message.
type fakeEngine struct {
	api, min   string
	pullStream string // body of POST /images/create

	mu           sync.Mutex
	versionCalls int
	used         map[string]int // API version -> versioned requests
	netCreated   bool
	netBody      map[string]any
	created      bool
	createBody   map[string]any
}

var versionedPath = regexp.MustCompile(`^/v([0-9]+\.[0-9]+)(/.*)$`)

func apiLess(a, b string) bool {
	va, _ := parseVersionForTest(a)
	vb, _ := parseVersionForTest(b)
	return va[0] < vb[0] || (va[0] == vb[0] && va[1] < vb[1])
}

func parseVersionForTest(s string) ([2]int, error) {
	a, b, _ := strings.Cut(s, ".")
	x, err := strconv.Atoi(a)
	if err != nil {
		return [2]int{}, err
	}
	y, err := strconv.Atoi(b)
	return [2]int{x, y}, err
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeEngine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path == "/version" && r.Method == http.MethodGet {
		f.versionCalls++
		writeJSON(w, 200, map[string]string{"Version": "29.1.3", "ApiVersion": f.api, "MinAPIVersion": f.min, "Os": "linux"})
		return
	}
	m := versionedPath.FindStringSubmatch(r.URL.Path)
	if m == nil {
		writeJSON(w, 404, map[string]string{"message": "page not found"})
		return
	}
	ver, rest := m[1], m[2]
	f.used[ver]++
	if apiLess(ver, f.min) {
		writeJSON(w, 400, map[string]string{"message": fmt.Sprintf("client version %s is too old. Minimum supported API version is %s, please upgrade your client to a newer version", ver, f.min)})
		return
	}
	if apiLess(f.api, ver) {
		writeJSON(w, 400, map[string]string{"message": fmt.Sprintf("client version %s is too new. Maximum supported API version is %s", ver, f.api)})
		return
	}
	switch {
	case r.Method == http.MethodGet && rest == "/info":
		writeJSON(w, 200, map[string]any{"ServerVersion": "29.1.3", "Runtimes": map[string]any{"runc": map[string]any{}}})
	case r.Method == http.MethodPost && rest == "/networks/create":
		_ = json.NewDecoder(r.Body).Decode(&f.netBody)
		f.netCreated = true
		writeJSON(w, 201, map[string]string{"Id": "net1"})
	case r.Method == http.MethodGet && strings.HasPrefix(rest, "/networks/"):
		if !f.netCreated {
			writeJSON(w, 404, map[string]string{"message": "network not found"})
			return
		}
		writeJSON(w, 200, map[string]any{"Id": "net1", "Name": strings.TrimPrefix(rest, "/networks/"),
			"IPAM":    map[string]any{"Config": []map[string]string{{"Subnet": "172.30.0.0/16", "Gateway": "172.30.0.1"}}},
			"Options": f.netBody["Options"]})
	case r.Method == http.MethodPost && rest == "/images/create":
		if r.URL.Query().Get("fromImage") == "" {
			writeJSON(w, 400, map[string]string{"message": "no fromImage"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(f.pullStream))
	case r.Method == http.MethodPost && rest == "/containers/create":
		_ = json.NewDecoder(r.Body).Decode(&f.createBody)
		f.created = true
		writeJSON(w, 201, map[string]any{"Id": "cid1", "Warnings": []string{}})
	case r.Method == http.MethodPost && strings.HasSuffix(rest, "/start"):
		w.WriteHeader(204)
	case r.Method == http.MethodGet && strings.HasPrefix(rest, "/containers/") && strings.HasSuffix(rest, "/json"):
		if !f.created {
			writeJSON(w, 404, map[string]string{"message": "No such container"})
			return
		}
		env := ""
		labels, _ := f.createBody["Labels"].(map[string]any)
		if v, ok := labels["org.opendeploy.environment"].(string); ok {
			env = v
		}
		writeJSON(w, 200, map[string]any{"Id": "cid1",
			"State":           map[string]any{"Status": "running", "Running": true, "StartedAt": "2026-10-01T00:00:00Z"},
			"Config":          map[string]any{"Labels": labels, "ExposedPorts": f.createBody["ExposedPorts"]},
			"NetworkSettings": map[string]any{"Networks": map[string]any{NetworkName(env): map[string]string{"IPAddress": "172.30.0.2"}}}})
	case r.Method == http.MethodGet && strings.HasPrefix(rest, "/containers/") && strings.HasSuffix(rest, "/logs"):
		if !f.created {
			writeJSON(w, 404, map[string]string{"message": "No such container"})
			return
		}
		w.Header().Set("Content-Type", "application/vnd.docker.multiplexed-stream")
		for _, fr := range []struct {
			stream byte
			text   string
		}{{1, "2026-10-01T00:00:01Z ready\n"}, {2, "2026-10-01T00:00:02Z warn\n"}} {
			hdr := make([]byte, 8)
			hdr[0] = fr.stream
			binary.BigEndian.PutUint32(hdr[4:], uint32(len(fr.text)))
			_, _ = w.Write(append(hdr, fr.text...))
		}
	default:
		writeJSON(w, 404, map[string]string{"message": "page not found: " + r.Method + " " + rest})
	}
}

func (f *fakeEngine) snapshot() (versionCalls int, used map[string]int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	used = map[string]int{}
	for k, v := range f.used {
		used[k] = v
	}
	return f.versionCalls, used
}

// startFakeEngine serves f on a unix socket, the transport NewDocker uses,
// and returns a client for it.
func startFakeEngine(t *testing.T, f *fakeEngine) *Docker {
	t.Helper()
	f.used = map[string]int{}
	if f.pullStream == "" {
		f.pullStream = `{"status":"Pulling from od/prj-x"}` + "\n" + `{"status":"Status: Downloaded newer image"}` + "\n"
	}
	// A short directory: unix socket paths are limited to ~100 bytes.
	dir, err := os.MkdirTemp("", "oddk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: f, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = hs.Serve(ln) }()
	t.Cleanup(func() { hs.Close() })
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock)
	}}
	t.Cleanup(tr.CloseIdleConnections)
	return &Docker{hc: &http.Client{Transport: tr}, SecretsDir: t.TempDir(), VolumesDir: t.TempDir(), Runsc: "runsc"}
}

// exercise runs the real network, pull, create/start, inspect and logs paths.
func exercise(ctx context.Context, d *Docker, s *Spec) (*Workload, []LogLine, error) {
	if _, err := d.Capabilities(ctx); err != nil {
		return nil, nil, fmt.Errorf("capabilities: %w", err)
	}
	if _, err := d.EnsureNetwork(ctx, NetworkSpec{EnvironmentID: s.EnvironmentID, ProjectID: s.ProjectID, Kind: "production"}); err != nil {
		return nil, nil, fmt.Errorf("network: %w", err)
	}
	w, err := d.Start(ctx, s, RegistryAuth{})
	if err != nil {
		return nil, nil, fmt.Errorf("start: %w", err)
	}
	logs, err := d.Logs(ctx, s.ID, 10, time.Time{})
	if err != nil {
		return nil, nil, fmt.Errorf("logs: %w", err)
	}
	return w, logs, nil
}

// B1 (release gate on Docker 29): the client hard-coded API 1.43, which
// Docker 29 (API 1.52, minimum 1.44) refuses with a 400. The client must
// negotiate the version from GET /version like the Docker CLI does.
func TestDockerAPIVersionNegotiation(t *testing.T) {
	for _, tc := range []struct {
		name, api, min string
		want           string // negotiated version
		checkDuplicate bool   // networks/create must ask for it (< 1.44)
	}{
		{name: "docker 29", api: "1.52", min: "1.44", want: "1.52"},
		{name: "newer than client", api: "1.56", min: "1.44", want: "1.52"},
		{name: "docker 28", api: "1.51", min: "1.24", want: "1.51"},
		{name: "docker 24", api: "1.43", min: "1.12", want: "1.43", checkDuplicate: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeEngine{api: tc.api, min: tc.min}
			d := startFakeEngine(t, f)
			s := goodSpec()
			w, logs, err := exercise(context.Background(), d, &s)
			if err != nil {
				t.Fatal(err)
			}
			if w.State != "running" || w.Endpoint != "172.30.0.2:8080" {
				t.Fatalf("workload %+v", w)
			}
			if len(logs) != 2 || logs[0] != (LogLine{Time: "2026-10-01T00:00:01Z", Stream: "stdout", Text: "ready"}) ||
				logs[1] != (LogLine{Time: "2026-10-01T00:00:02Z", Stream: "stderr", Text: "warn"}) {
				t.Fatalf("logs %+v", logs)
			}
			calls, used := f.snapshot()
			if calls != 1 {
				t.Errorf("GET /version called %d times, want once (cached per client)", calls)
			}
			if len(used) != 1 || used[tc.want] == 0 {
				t.Errorf("versioned requests by API version: %v, want all at %s", used, tc.want)
			}
			f.mu.Lock()
			netBody, createBody := f.netBody, f.createBody
			f.mu.Unlock()
			if _, ok := netBody["CheckDuplicate"]; ok != tc.checkDuplicate {
				t.Errorf("networks/create CheckDuplicate sent=%v, want %v (body %v)", ok, tc.checkDuplicate, netBody)
			}
			if _, ok := createBody["MacAddress"]; ok {
				t.Errorf("containers/create sends container-wide MacAddress (removed in API 1.52)")
			}
			host, _ := createBody["HostConfig"].(map[string]any)
			if cd, _ := host["CapDrop"].([]any); len(cd) != 1 || cd[0] != "ALL" || host["Privileged"] != false {
				t.Errorf("hardening not sent: %v", host)
			}
		})
	}
}

// An engine outside the range the client supports is refused with a clear
// error before any versioned request is sent.
func TestDockerAPIVersionUnsupported(t *testing.T) {
	for _, tc := range []struct {
		name, api, min string
		want           []string
	}{
		{name: "engine requires newer client", api: "1.60", min: "1.53", want: []string{"requires API version 1.53 or newer", "at most 1.52"}},
		{name: "engine too old", api: "1.41", min: "1.12", want: []string{"engine API version 1.41 is older than 1.43"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeEngine{api: tc.api, min: tc.min}
			d := startFakeEngine(t, f)
			s := goodSpec()
			_, _, err := exercise(context.Background(), d, &s)
			if err == nil {
				t.Fatal("unsupported engine accepted")
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q does not contain %q", err, w)
				}
			}
			if _, used := f.snapshot(); len(used) != 0 {
				t.Errorf("versioned requests sent to an unsupported engine: %v", used)
			}
		})
	}
}

// Concurrent first requests negotiate once.
func TestDockerAPIVersionNegotiatedOnce(t *testing.T) {
	f := &fakeEngine{api: "1.52", min: "1.44"}
	d := startFakeEngine(t, f)
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := d.Capabilities(context.Background())
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if calls, used := f.snapshot(); calls != 1 || used["1.52"] != 16 {
		t.Fatalf("version calls %d, requests %v", calls, used)
	}
}

// API 1.48 deprecated the "error" field of the pull progress stream; newer
// engines may report a failure only in "errorDetail". It must still fail
// the start instead of creating a container from a missing image.
func TestDockerPullErrorDetail(t *testing.T) {
	f := &fakeEngine{api: "1.43", min: "1.12",
		pullStream: `{"status":"Pulling"}` + "\n" + `{"errorDetail":{"message":"manifest unknown"}}` + "\n"}
	d := startFakeEngine(t, f)
	s := goodSpec()
	_, _, err := exercise(context.Background(), d, &s)
	if err == nil || !strings.Contains(err.Error(), "manifest unknown") {
		t.Fatalf("pull failure not reported: %v", err)
	}
	f.mu.Lock()
	created := f.created
	f.mu.Unlock()
	if created {
		t.Fatal("container created after a failed pull")
	}
}
