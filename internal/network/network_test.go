package network

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/ids"
)

func pol(bridge, subnet string, internet bool) EnvPolicy {
	return EnvPolicy{EnvironmentID: ids.New("env"), ProjectID: ids.New("prj"), Kind: "production", Bridge: bridge, Subnet: subnet, Internet: internet}
}

func TestRenderOrderAndContent(t *testing.T) {
	a := pol("oda", "172.30.1.0/24", true)
	b := pol("odb", "172.30.2.0/24", false)
	r := Ruleset{Envs: []EnvPolicy{a, b}, BuildBridges: []string{"docker0"}, ProxyPort: 3128, DNS: []string{"192.168.1.1"}}
	s, err := r.Render()
	if err != nil {
		t.Fatal(err)
	}
	intra := strings.Index(s, `iifname "oda" oifname "oda" accept`)
	priv := strings.Index(s, `iifname "oda" ip daddr @blocked4 drop`)
	dns := strings.Index(s, `iifname "oda" ip daddr { 192.168.1.1 }`)
	if intra < 0 || priv < 0 || dns < 0 || !(intra < priv && dns < priv) {
		t.Fatalf("rule ordering wrong:\n%s", s)
	}
	if !strings.Contains(s, `iifname "odb" oifname != "odb" drop comment "no internet`) {
		t.Fatal("offline env not isolated")
	}
	if strings.Contains(s, `iifname "odb" ip daddr { 192.168.1.1 }`) {
		t.Fatal("offline env should not get DNS egress")
	}
	if !strings.Contains(s, `iifname @workload_bridges drop comment "workload->host"`) {
		t.Fatal("workload->host drop missing")
	}
	if !strings.HasPrefix(s, "table inet opendeploy\ndelete table inet opendeploy\n") {
		t.Fatal("not an atomic replace")
	}
}

func TestRenderValidation(t *testing.T) {
	bad := []Ruleset{
		{Envs: []EnvPolicy{pol("od a; flush ruleset", "172.30.1.0/24", true)}},
		{Envs: []EnvPolicy{pol("oda", "not-a-subnet", true)}},
		{BuildBridges: []string{"docker0\"; drop"}},
		{DNS: []string{"8.8.8.8; accept"}},
	}
	for i, r := range bad {
		if _, err := r.Render(); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	p := pol("oda", "172.30.1.0/24", true)
	p.Kind, p.AllowPrivate = "preview", true
	if p.Validate() == nil {
		t.Fatal("preview with private access accepted")
	}
}

func TestServiceApplyRollsBackOnFailure(t *testing.T) {
	calls := 0
	s := &Service{ApplyFn: func(ctx context.Context, script string) error {
		calls++
		if calls == 2 {
			return errors.New("nft failed")
		}
		return nil
	}}
	if err := s.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(context.Background(), pol("oda", "172.30.1.0/24", true)); err == nil {
		t.Fatal("expected failure")
	}
	st, _ := s.Status(context.Background())
	if st.Enforcing || st.Envs != 0 {
		t.Fatalf("%+v", st)
	}
}

func TestProxyPolicyAndSSRF(t *testing.T) {
	s := &Service{ApplyFn: func(context.Context, string) error { return nil }}
	_ = s.Init(context.Background())
	restricted := pol("oda", "172.30.1.0/24", false)
	restricted.AllowHosts = []string{"api.example.com", "*.pkg.dev"}
	_ = s.Apply(context.Background(), restricted)

	allow, anyHost, ok := s.ProxyPolicy(netip.MustParseAddr("172.30.1.5"))
	if !ok || anyHost || len(allow) != 2 {
		t.Fatalf("%v %v %v", allow, anyHost, ok)
	}
	if !hostAllowed("x.pkg.dev", allow) || hostAllowed("pkg.dev", allow) || hostAllowed("evil.com", allow) || !hostAllowed("API.example.com.", allow) {
		t.Fatal("allowlist matching")
	}
	if _, _, ok := s.ProxyPolicy(netip.MustParseAddr("8.8.8.8")); ok {
		t.Fatal("public source allowed to use proxy")
	}

	// End-to-end: the proxy refuses private destinations even when the
	// hostname is allowlisted (DNS rebinding / SSRF).
	p := &Proxy{Policy: func(netip.Addr) ([]string, bool, bool) { return nil, true, true }, Resolver: &net.Resolver{PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, errors.New("no dns in test")
		}}}
	srv := httptest.NewServer(p)
	defer srv.Close()
	pu, _ := url.Parse(srv.URL)
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
	for _, target := range []string{"http://127.0.0.1:1/", "http://169.254.169.254/latest/meta-data/", "http://10.0.0.1/"} {
		res, err := c.Get(target)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != 403 || !strings.Contains(string(b), "not a public address") {
			t.Fatalf("%s: %d %s", target, res.StatusCode, b)
		}
	}
	req, _ := http.NewRequest("CONNECT", srv.URL, nil)
	req.Host = "10.1.2.3:443"
	res, err := http.DefaultClient.Do(req)
	if err == nil {
		res.Body.Close()
		if res.StatusCode != 403 {
			t.Fatalf("CONNECT to private: %d", res.StatusCode)
		}
	}
}

func TestResolvConf(t *testing.T) {
	f := t.TempDir() + "/resolv.conf"
	_ = writeFile(f, "nameserver 127.0.0.53\nnameserver 192.168.1.1\nnameserver 2001:4860:4860::8888\nsearch lan\n")
	got := ResolvConfServers(f)
	if len(got) != 2 || got[0] != "192.168.1.1" {
		t.Fatalf("%v", got)
	}
}

func writeFile(p, s string) error { return os.WriteFile(p, []byte(s), 0o644) }
