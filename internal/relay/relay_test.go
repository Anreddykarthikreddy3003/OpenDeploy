package relay

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"log/slog"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/domains"
)

const (
	suffix     = "relay-edge.net"
	tunnelName = "tunnel.relay-edge.net"
	secret     = "Bearer TOP-SECRET-TOKEN-7f3a"
	cookie     = "session=TOP-SECRET-COOKIE-91bd"
)

// ---- fixtures --------------------------------------------------------------

type fakeDNS struct {
	mu  sync.Mutex
	txt map[string][]string
}

func (f *fakeDNS) set(name string, v ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.txt[name] = v
}

func (f *fakeDNS) TXT(_ context.Context, name string) (*domains.TXTResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return &domains.TXTResult{Name: name, Zone: "z", Servers: []domains.ServerAnswer{{Server: "198.51.100.1:53", Authoritative: true, Records: f.txt[name]}}}, nil
}

func (f *fakeDNS) Resolve(context.Context, string) (*domains.Resolution, error) {
	return &domains.Resolution{}, nil
}

// publicCA stands in for a public ACME CA trusted by browsers; only the
// local edges (never the relay) hold leaf keys it issued.
type publicCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newPublicCA(t *testing.T) *publicCA {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Public CA"}, IsCA: true, BasicConstraintsValid: true,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	p := x509.NewCertPool()
	p.AddCert(c)
	return &publicCA{cert: c, key: k, pool: p}
}

func (ca *publicCA) leaf(t *testing.T, names ...string) tls.Certificate {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, &k.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

// edge is a node's local Caddy stand-in: HTTPS with its own certificate
// plus plain HTTP.
type edge struct {
	https, http *httptest.Server
	name        string
}

func newEdge(t *testing.T, ca *publicCA, name string, hosts ...string) *edge {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: strings.TrimPrefix(cookie, "session=")})
		fmt.Fprintf(w, "edge=%s host=%s auth=%s", name, r.Host, r.Header.Get("Authorization"))
	})
	hs := httptest.NewUnstartedServer(h)
	hs.TLS = &tls.Config{Certificates: []tls.Certificate{ca.leaf(t, hosts...)}, MinVersion: tls.VersionTLS12}
	hs.StartTLS()
	t.Cleanup(hs.Close)
	hp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+r.Host+r.URL.Path, http.StatusPermanentRedirect)
	}))
	t.Cleanup(hp.Close)
	return &edge{https: hs, http: hp, name: name}
}

type rig struct {
	t      *testing.T
	s      *Server
	dns    *fakeDNS
	tunnel string
	https  string
	http   string
	ca     *publicCA
	mu     sync.Mutex
	tapped bytes.Buffer
}

func newRig(t *testing.T, mod func(*ServerConfig)) *rig {
	t.Helper()
	r := &rig{t: t, dns: &fakeDNS{txt: map[string][]string{}}, ca: newPublicCA(t)}
	cfg := ServerConfig{DataDir: t.TempDir(), TunnelNames: []string{tunnelName}, PublicSuffix: suffix, DNS: r.dns, AuditPath: "-",
		AuthRecheck: 100 * time.Millisecond, ProofRecheck: 200 * time.Millisecond}
	if mod != nil {
		mod(&cfg)
	}
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s.tap = func(_ string, _ bool, p []byte) {
		r.mu.Lock()
		r.tapped.Write(p)
		r.mu.Unlock()
	}
	r.s = s
	lt, _ := net.Listen("tcp", "127.0.0.1:0")
	ls, _ := net.Listen("tcp", "127.0.0.1:0")
	lh, _ := net.Listen("tcp", "127.0.0.1:0")
	r.tunnel, r.https, r.http = lt.Addr().String(), ls.Addr().String(), lh.Addr().String()
	go s.ServeTunnel(lt)
	go s.ServeHTTPS(ls)
	go s.ServeHTTP(lh)
	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)
	t.Cleanup(func() { cancel(); s.Close() })
	return r
}

func (r *rig) token(tenant, instance string) string {
	tok, err := r.s.Reg.CreateToken(r.s.CA, tenant, instance, time.Hour)
	if err != nil {
		r.t.Fatal(err)
	}
	return tok.String()
}

func (r *rig) agent(token string, e *edge, hosts ...string) (*Agent, context.CancelFunc, string) {
	dir := r.t.TempDir()
	a := NewAgent(AgentConfig{ServerAddr: r.tunnel, ServerName: tunnelName, StateDir: dir, EnrollToken: token,
		LocalHTTPS: e.https.Listener.Addr().String(), LocalHTTP: e.http.Listener.Addr().String(), SyncInterval: 100 * time.Millisecond,
		Hosts: func(context.Context) ([]string, error) { return hosts, nil }, Log: slog.New(slog.NewTextHandler(os.Stderr, nil))})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		if err := a.Run(ctx); err != nil {
			r.t.Logf("agent: %v", err)
		}
	}()
	r.t.Cleanup(cancel)
	return a, cancel, dir
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (r *rig) routedTo(host string) string {
	id, ok := r.s.Lookup(host)
	if !ok {
		return ""
	}
	return id.Instance
}

func (r *rig) get(host string) (string, error) {
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: r.ca.pool, ServerName: host},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", r.https)
		}}}
	req, _ := http.NewRequest("GET", "https://"+host+"/account", nil)
	req.Header.Set("Authorization", secret)
	res, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return string(b) + " set-cookie=" + res.Header.Get("Set-Cookie"), nil
}

// ---- tests -----------------------------------------------------------------

// ST-07 / Q27 / Q62: the relay forwards only TLS ciphertext; plaintext
// (request auth header, response cookie and body) never crosses it, and the
// certificate key lives only at the local edge.
func TestRelayCarriesOnlyCiphertext(t *testing.T) {
	r := newRig(t, nil)
	hostA := "app.inst-a." + suffix
	e := newEdge(t, r.ca, "a", hostA)
	a, _, _ := r.agent(r.token("acme", "inst-a"), e, hostA)
	waitFor(t, "route", func() bool { return r.routedTo(hostA) == "inst-a" })

	body, err := r.get(hostA)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "edge=a") || !strings.Contains(body, secret) || !strings.Contains(body, strings.TrimPrefix(cookie, "session=")) {
		t.Fatalf("end-to-end response: %s", body)
	}
	r.mu.Lock()
	seen := r.tapped.Bytes()
	r.mu.Unlock()
	if len(seen) < 500 {
		t.Fatalf("tap captured too little (%d bytes)", len(seen))
	}
	for _, needle := range []string{secret, "TOP-SECRET", "/account", "edge=a", "Authorization"} {
		if bytes.Contains(seen, []byte(needle)) {
			t.Fatalf("relay observed plaintext %q", needle)
		}
	}
	if !bytes.Contains(seen, []byte(hostA)) {
		t.Fatal("expected SNI (metadata) to be visible to the relay")
	}
	// The relay's data directory holds only its own CA/registry material.
	_ = filepath.Walk(r.s.cfg.DataDir, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			b, _ := os.ReadFile(p)
			for _, c := range e.https.TLS.Certificates {
				if bytes.Contains(b, c.Certificate[0]) {
					t.Fatalf("edge certificate material found at relay: %s", p)
				}
			}
		}
		return nil
	})
	// Plain HTTP is routed by Host (redirects / ACME HTTP-01).
	res, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", r.http)
		}}}).Get("http://" + hostA + "/x")
	if err != nil || res.StatusCode != http.StatusPermanentRedirect {
		t.Fatalf("http routing: %v %v", err, res)
	}
	res.Body.Close()
	// Unknown hosts get nothing.
	res, err = (&http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", r.http)
	}}}).Get("http://unknown.example.org/")
	if err != nil || res.StatusCode != 404 {
		t.Fatalf("unknown host: %v %v", err, res)
	}
	res.Body.Close()
	if st := a.Status(); !st.Connected || st.Instance != "inst-a" || len(st.Accepted) != 1 {
		t.Fatalf("agent status %+v", st)
	}
}

// Q28 / Q76: a compromised relay that reroutes a domain to another
// instance cannot impersonate it: the client's certificate check fails.
func TestCompromisedRelayMisrouteFailsTLS(t *testing.T) {
	r := newRig(t, nil)
	hostA, hostB := "app.inst-a."+suffix, "app.inst-b."+suffix
	r.agent(r.token("acme", "inst-a"), newEdge(t, r.ca, "a", hostA), hostA)
	// Instance B colludes with the relay: its agent is willing to forward
	// A's hostname, but B's edge has no certificate for it.
	r.agent(r.token("globex", "inst-b"), newEdge(t, r.ca, "b", hostB), hostB, hostA)
	waitFor(t, "routes", func() bool { return r.routedTo(hostA) == "inst-a" && r.routedTo(hostB) == "inst-b" })
	// Simulate the compromise: point A's hostname at B's tunnel.
	r.s.mu.Lock()
	r.s.routes[hostA] = &route{host: hostA, sess: r.s.sessions["inst-b"]}
	r.s.mu.Unlock()
	_, err := r.get(hostA)
	var herr x509.HostnameError
	if err == nil || !errors.As(err, &herr) {
		t.Fatalf("misrouted connection must fail certificate validation, got: %v", err)
	}
}

// Q29 / Q30: an instance can only route its own namespace and custom
// domains whose owner published a record naming that instance; hostnames
// cannot be taken over from another tenant, and every denial is audited.
func TestCrossTenantRoutesDenied(t *testing.T) {
	r := newRig(t, nil)
	hostA, hostB := "app.inst-a."+suffix, "app.inst-b."+suffix
	custom := "shop.acme-corp.com"
	r.dns.set(domains.ChallengeName(custom), domains.TXTValue("inst-a", "tok"))
	r.agent(r.token("acme", "inst-a"), newEdge(t, r.ca, "a", hostA, custom), hostA, custom)
	waitFor(t, "a routes", func() bool { return r.routedTo(hostA) == "inst-a" && r.routedTo(custom) == "inst-a" })

	b, _, _ := r.agent(r.token("globex", "inst-b"), newEdge(t, r.ca, "b", hostB), hostB, hostA, custom, "x.inst-c."+suffix, suffix, "evil.acme-corp.com")
	waitFor(t, "b ack", func() bool { return b.Status().Connected })
	st := b.Status()
	if len(st.Accepted) != 1 || st.Accepted[0] != hostB {
		t.Fatalf("instance B accepted foreign routes: %+v", st)
	}
	for _, h := range []string{hostA, custom, "x.inst-c." + suffix, suffix, "evil.acme-corp.com"} {
		if _, ok := st.Rejected[h]; !ok {
			t.Fatalf("%s not rejected: %+v", h, st.Rejected)
		}
	}
	if r.routedTo(hostA) != "inst-a" || r.routedTo(custom) != "inst-a" {
		t.Fatal("routes of instance A were disturbed")
	}
	if n := len(r.s.Audit.Find("route.authorize", "denied")); n < 5 {
		t.Fatalf("denials not audited: %d", n)
	}
	// Even if the domain owner (DNS) later names B too, A keeps the route
	// while connected: no silent takeover of a live hostname.
	r.dns.set(domains.ChallengeName(custom), domains.TXTValue("inst-a", "tok"), domains.TXTValue("inst-b", "tok2"))
	time.Sleep(300 * time.Millisecond)
	if r.routedTo(custom) != "inst-a" {
		t.Fatal("live hostname taken over")
	}
	// When the owner removes A's record, the relay withdraws A's route.
	r.dns.set(domains.ChallengeName(custom), domains.TXTValue("inst-b", "tok2"))
	waitFor(t, "withdrawal", func() bool { return r.routedTo(custom) != "inst-a" })
	if len(r.s.Audit.Find("route.withdraw", "")) == 0 {
		t.Fatal("withdrawal not audited")
	}
}

// Q29 / Q77: credentials are one-time/pinned to enroll, short-lived and
// renewed live, revocable, and rotation invalidates stolen copies.
func TestCredentialLifecycle(t *testing.T) {
	r := newRig(t, func(c *ServerConfig) { c.CertTTL = 3 * time.Second })
	hostA := "app.inst-a." + suffix
	e := newEdge(t, r.ca, "a", hostA)
	tok := r.token("acme", "inst-a")

	// A token presented to a different relay (other CA) is refused by the
	// agent's pin before anything is sent.
	other := newRig(t, nil)
	bad := NewAgent(AgentConfig{ServerAddr: other.tunnel, ServerName: tunnelName, StateDir: t.TempDir(), EnrollToken: tok})
	if err := bad.Enroll(context.Background()); err == nil || !strings.Contains(err.Error(), "pinned") {
		t.Fatalf("enrolled against an unpinned relay: %v", err)
	}

	a, stopA, dirA := r.agent(tok, e, hostA)
	waitFor(t, "route", func() bool { return r.routedTo(hostA) == "inst-a" })
	// Tokens are single use.
	again := NewAgent(AgentConfig{ServerAddr: r.tunnel, ServerName: tunnelName, StateDir: t.TempDir(), EnrollToken: tok})
	if err := again.Enroll(context.Background()); err == nil {
		t.Fatal("enrollment token reused")
	}
	// Live renewal keeps the tunnel beyond the first certificate's expiry.
	first := a.Status().CertUntil
	time.Sleep(time.Until(first) + 500*time.Millisecond)
	if st := a.Status(); !st.CertUntil.After(first) || r.routedTo(hostA) != "inst-a" {
		t.Fatalf("credential not renewed live: %+v first=%v", st, first)
	}
	if len(r.s.Audit.Find("tunnel.renew", "success")) == 0 {
		t.Fatal("renewal not audited")
	}

	// A stolen copy of the credential stops working after rotation.
	stolen := t.TempDir()
	for _, f := range []string{"agent.key", "agent.crt", "ca.crt"} {
		b, _ := os.ReadFile(filepath.Join(dirA, f))
		_ = os.WriteFile(filepath.Join(stolen, f), b, 0o600)
	}
	stopA()
	waitFor(t, "a down", func() bool { return r.routedTo(hostA) == "" })
	thief := NewAgent(AgentConfig{ServerAddr: r.tunnel, ServerName: tunnelName, StateDir: stolen, LocalHTTPS: "127.0.0.1:1", LocalHTTP: "127.0.0.1:1",
		SyncInterval: 100 * time.Millisecond, Hosts: func(context.Context) ([]string, error) { return []string{hostA}, nil }})
	if err := thief.loadCredentials(); err != nil {
		t.Fatal(err)
	}
	a2, _, _ := r.agent(r.token("acme", "inst-a"), e, hostA) // operator re-enrolls (rotation)
	waitFor(t, "rotated route", func() bool { return r.routedTo(hostA) == "inst-a" && a2.Status().Connected })
	denied := len(r.s.Audit.Find("tunnel.auth", "denied"))
	tctx, tcancel := context.WithTimeout(context.Background(), 2*time.Second)
	_ = thief.session(tctx)
	tcancel()
	if len(r.s.Audit.Find("tunnel.auth", "denied")) <= denied {
		t.Fatal("stolen pre-rotation credential was not refused")
	}

	// Revocation closes the live tunnel and blocks reconnection.
	if err := r.s.Reg.Revoke("inst-a"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "revocation", func() bool { return r.routedTo(hostA) == "" })
	time.Sleep(300 * time.Millisecond)
	if r.routedTo(hostA) != "" {
		t.Fatal("revoked instance reconnected")
	}

	// A certificate from a foreign CA never establishes a tunnel.
	foreign := newPublicCA(t)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id := Identity{Tenant: "acme", Instance: "inst-a"}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(9), URIs: nil, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	tpl.URIs = append(tpl.URIs, id.URI())
	der, _ := x509.CreateCertificate(rand.Reader, tpl, foreign.cert, &k.PublicKey, foreign.key)
	pool := x509.NewCertPool()
	pool.AddCert(r.s.CA.Cert)
	c, err := tls.Dial("tcp", r.tunnel, &tls.Config{RootCAs: pool, ServerName: tunnelName, NextProtos: []string{ALPNTunnel},
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: k}}})
	if err == nil {
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		_, rerr := c.Read(make([]byte, 1))
		c.Close()
		if rerr == nil {
			t.Fatal("foreign-CA credential accepted")
		}
	}
}

func TestPeekSNI(t *testing.T) {
	cl, sv := net.Pipe()
	go func() {
		c := tls.Client(cl, &tls.Config{ServerName: "App.Example.ORG", InsecureSkipVerify: true})
		_ = c.Handshake()
	}()
	host, raw, err := PeekSNI(sv, time.Second)
	if err != nil || host != "app.example.org" || len(raw) == 0 || raw[0] != 0x16 {
		t.Fatalf("%q %v %d", host, err, len(raw))
	}
	cl2, sv2 := net.Pipe()
	go func() { _, _ = cl2.Write([]byte("GET / HTTP/1.1\r\nHost: www.Example.org:80\r\n\r\n")) }()
	host, raw, err = PeekHost(sv2, time.Second)
	if err != nil || host != "www.example.org" || !bytes.HasPrefix(raw, []byte("GET / ")) {
		t.Fatalf("%q %v %q", host, err, raw)
	}
	// Garbage is rejected quickly.
	cl3, sv3 := net.Pipe()
	go func() { _, _ = cl3.Write(bytes.Repeat([]byte{0x16, 0x03, 0x01, 0xff, 0xff}, 10)); cl3.Close() }()
	if _, _, err := PeekSNI(sv3, time.Second); err == nil {
		t.Fatal("garbage accepted")
	}
}

func FuzzPeekSNI(f *testing.F) {
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00})
	f.Fuzz(func(t *testing.T, b []byte) {
		cl, sv := net.Pipe()
		go func() { _, _ = cl.Write(b); cl.Close() }()
		_, _, _ = PeekSNI(sv, 200*time.Millisecond)
		sv.Close()
	})
}
