//go:build e2e

package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/allinone"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/config"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/domains"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/testcap"
)

// zone is served by authZone, a real authoritative DNS server on loopback.
const zone = "opendeploy-acme-e2e.dev." // never leaves loopback: every lookup goes to authZone

// authZone answers authoritatively for zone: an NS set, every name resolves
// to 127.0.0.1, and TXT records are whatever the test publishes.
type authZone struct {
	mu  sync.Mutex
	txt map[string]string
}

func (z *authZone) setTXT(name, value string) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.txt[dns.Fqdn(strings.ToLower(name))] = value
}

func (z *authZone) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	q := req.Question[0]
	name := strings.ToLower(q.Name)
	if !dns.IsSubDomain(zone, name) {
		m.Rcode = dns.RcodeRefused
		_ = w.WriteMsg(m)
		return
	}
	m.Authoritative = true
	hdr := func(t uint16) dns.RR_Header {
		return dns.RR_Header{Name: q.Name, Rrtype: t, Class: dns.ClassINET, Ttl: 5}
	}
	switch q.Qtype {
	case dns.TypeNS:
		if name == zone {
			m.Answer = append(m.Answer, &dns.NS{Hdr: hdr(dns.TypeNS), Ns: "ns1." + zone})
		}
	case dns.TypeA:
		m.Answer = append(m.Answer, &dns.A{Hdr: hdr(dns.TypeA), A: net.IPv4(127, 0, 0, 1)})
	case dns.TypeTXT:
		z.mu.Lock()
		v, ok := z.txt[name]
		z.mu.Unlock()
		if ok {
			m.Answer = append(m.Answer, &dns.TXT{Hdr: hdr(dns.TypeTXT), Txt: []string{v}})
		}
	}
	if len(m.Answer) == 0 {
		m.Ns = append(m.Ns, &dns.SOA{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 5},
			Ns: "ns1." + zone, Mbox: "hostmaster." + zone, Serial: 1, Refresh: 60, Retry: 60, Expire: 600, Minttl: 5})
	}
	_ = w.WriteMsg(m)
}

// serveZone starts UDP and TCP listeners on the same loopback port.
func serveZone(t *testing.T, z *authZone) string {
	t.Helper()
	for i := 0; i < 20; i++ {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ln, err := net.Listen("tcp", pc.LocalAddr().String())
		if err != nil {
			pc.Close()
			continue
		}
		udp, tcp := &dns.Server{PacketConn: pc, Handler: z}, &dns.Server{Listener: ln, Handler: z}
		go func() { _ = udp.ActivateAndServe() }()
		go func() { _ = tcp.ActivateAndServe() }()
		t.Cleanup(func() { _ = udp.Shutdown(); _ = tcp.Shutdown() })
		return pc.LocalAddr().String()
	}
	t.Fatal("no free port for the DNS server")
	return ""
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// directoryTLS writes a private CA and a 127.0.0.1 server certificate for
// Pebble's ACME directory, as an operator of a private ACME CA would have.
func directoryTLS(t *testing.T, dir string) (caFile, certFile, keyFile string) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "e2e ACME directory CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "127.0.0.1"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, DNSNames: []string{"localhost"},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	caFile, certFile, keyFile = filepath.Join(dir, "ca.pem"), filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	for f, b := range map[string]*pem.Block{caFile: {Type: "CERTIFICATE", Bytes: caDER}, certFile: {Type: "CERTIFICATE", Bytes: leafDER}, keyFile: {Type: "EC PRIVATE KEY", Bytes: keyDER}} {
		if err := os.WriteFile(f, pem.EncodeToMemory(b), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return caFile, certFile, keyFile
}

// TestACMEIssuance proves the direct-ingress HTTPS path against a real ACME
// server (Pebble, Let's Encrypt's test CA): a custom domain is claimed,
// proven through authoritative TXT, validated by the CA over HTTP-01
// against the real Caddy edge, served with a certificate that chains to the
// CA, and detached.
func TestACMEIssuance(t *testing.T) {
	caddy, err := exec.LookPath("caddy")
	if err != nil {
		testcap.Blocked(t, "caddy not on PATH")
	}
	pebble, err := exec.LookPath("pebble")
	if err != nil {
		testcap.Blocked(t, "pebble (ACME test server) not on PATH")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		testcap.Blocked(t, "docker daemon unavailable")
	}
	dir := t.TempDir()
	z := &authZone{txt: map[string]string{}}
	dnsAddr := serveZone(t, z)
	_, dnsPort, _ := net.SplitHostPort(dnsAddr)

	httpPort, httpsPort := freeTCPPort(t), freeTCPPort(t)
	acmePort, mgmtPort := freeTCPPort(t), freeTCPPort(t)
	caFile, certFile, keyFile := directoryTLS(t, dir)
	pcfg, _ := json.Marshal(map[string]any{"pebble": map[string]any{
		"listenAddress": fmt.Sprintf("127.0.0.1:%d", acmePort), "managementListenAddress": fmt.Sprintf("127.0.0.1:%d", mgmtPort),
		"certificate": certFile, "privateKey": keyFile, "httpPort": httpPort, "tlsPort": httpsPort,
		"ocspResponderURL": "", "externalAccountBindingRequired": false,
	}})
	cfgFile := filepath.Join(dir, "pebble.json")
	_ = os.WriteFile(cfgFile, pcfg, 0o644)
	pb := exec.Command(pebble, "-config", cfgFile, "-dnsserver", dnsAddr, "-strict=false")
	pb.Env = append(os.Environ(), "PEBBLE_VA_NOSLEEP=1", "PEBBLE_WFE_NONCEREJECT=0")
	plog, _ := os.Create(filepath.Join(dir, "pebble.log"))
	pb.Stdout, pb.Stderr = plog, plog
	if err := pb.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pb.Process.Kill(); _ = pb.Wait() })
	defer func() {
		if t.Failed() {
			b, _ := os.ReadFile(plog.Name())
			t.Logf("pebble log:\n%s", b)
		}
	}()
	caPEM, _ := os.ReadFile(caFile)
	dirPool := x509.NewCertPool()
	dirPool.AppendCertsFromPEM(caPEM)
	mgmt := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: dirPool}}}
	waitHTTP(t, mgmt, fmt.Sprintf("https://127.0.0.1:%d/dir", acmePort))

	ctx := context.Background()
	s, err := allinone.Start(ctx, allinone.Options{DataDir: t.TempDir(), CaddyBin: caddy, HTTPPort: httpPort,
		DNS: &domains.Resolver{Recursive: []string{dnsAddr}, Port: dnsPort, AllowPrivateNS: true},
		Mutate: func(n *config.Node) {
			n.Ingress.Mode = "direct"
			n.Ingress.BaseDomain = "apps." + strings.TrimSuffix(zone, ".")
			n.Ingress.PublicIPv4 = "127.0.0.1"
			n.Ingress.HTTPSPort = httpsPort
			n.Ingress.ACMEEmail = "ops@example.com"
			n.Ingress.ACMECA = fmt.Sprintf("https://127.0.0.1:%d/dir", acmePort)
			n.Ingress.ACMECARoot = caFile
		}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c := bootstrap(t, s)
	projectID := deployDir(t, c, "shop", "fixtures/static", nil)

	// Claim, publish the TXT proof on the authoritative server, verify.
	host := "shop." + strings.TrimSuffix(zone, ".")
	var claim struct {
		ID           string `json:"id"`
		Instructions struct {
			TXTName  string `json:"txt_name"`
			TXTValue string `json:"txt_value"`
		} `json:"instructions"`
	}
	if code := c.json("POST", "/api/v2/projects/"+projectID+"/domains", map[string]string{"hostname": host}, &claim); code != 201 {
		t.Fatalf("claim %d", code)
	}
	if code := c.json("POST", "/api/v2/domains/"+claim.ID+"/verify", nil, nil); code != 422 {
		t.Fatalf("verify without the TXT record: %d, want 422", code)
	}
	z.setTXT(claim.Instructions.TXTName, claim.Instructions.TXTValue)
	if code := c.json("POST", "/api/v2/domains/"+claim.ID+"/verify", nil, nil); code != 200 {
		t.Fatalf("verify %d", code)
	}

	// The platform's own TLS check reports the certificate as active.
	deadline := time.Now().Add(4 * time.Minute)
	var dom struct {
		Status    string `json:"status"`
		TLSStatus string `json:"tls_status"`
	}
	for time.Now().Before(deadline) {
		c.json("GET", "/api/v2/domains/"+claim.ID, nil, &dom)
		if dom.TLSStatus == "active" || dom.TLSStatus == "error" {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if dom.Status != "active" || dom.TLSStatus != "active" {
		t.Fatalf("domain %+v after ACME issuance", dom)
	}

	// Independently: the edge serves the app over HTTPS with a certificate
	// that chains to the ACME CA's root.
	roots := x509.NewCertPool()
	res, err := mgmt.Get(fmt.Sprintf("https://127.0.0.1:%d/roots/0", mgmtPort))
	if err != nil {
		t.Fatal(err)
	}
	rootPEM, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if !roots.AppendCertsFromPEM(rootPEM) {
		t.Fatalf("pebble root: %q", rootPEM)
	}
	edge := func(h string) (*http.Response, error) {
		tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: h},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, fmt.Sprintf("127.0.0.1:%d", httpsPort))
			}}
		defer tr.CloseIdleConnections()
		return (&http.Client{Transport: tr, Timeout: 10 * time.Second}).Get("https://" + h + "/")
	}
	for _, h := range []string{host, "shop.apps." + strings.TrimSuffix(zone, ".")} {
		var body []byte
		var lastErr error
		for i := 0; i < 60; i++ { // the generated host may still be issuing
			res, err := edge(h)
			if err == nil {
				body, _ = io.ReadAll(res.Body)
				res.Body.Close()
				lastErr = nil
				if res.StatusCode == 200 {
					break
				}
				lastErr = fmt.Errorf("status %d", res.StatusCode)
			} else {
				lastErr = err
			}
			time.Sleep(2 * time.Second)
		}
		if lastErr != nil || !strings.Contains(string(body), "hello from static") {
			t.Fatalf("https://%s: %v %q", h, lastErr, body)
		}
	}
	// Plain HTTP redirects to HTTPS for ACME hosts.
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/", httpPort), nil)
	req.Host = host
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if res, err := noFollow.Do(req); err != nil || res.StatusCode/100 != 3 || !strings.HasPrefix(res.Header.Get("Location"), "https://"+host) {
		t.Fatalf("http -> https redirect: %v %v", res, err)
	}

	// Detach: the domain is tombstoned and no longer served.
	if code := c.json("DELETE", "/api/v2/domains/"+claim.ID, nil, nil); code/100 != 2 {
		t.Fatalf("detach %d", code)
	}
	for i := 0; i < 30; i++ {
		res, err := edge(host)
		if err != nil || res.StatusCode != 200 {
			if res != nil {
				res.Body.Close()
			}
			return
		}
		res.Body.Close()
		time.Sleep(time.Second)
	}
	t.Fatal("detached domain is still served")
}

func waitHTTP(t *testing.T, hc *http.Client, url string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if res, err := hc.Get(url); err == nil {
			res.Body.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("%s did not come up", url)
}
