package platform

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/domains"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/store"
)

// fakeDNS is an authoritative view: TXT values per name (as served by all
// authoritative servers) and A records per host.
type fakeDNS struct {
	mu   sync.Mutex
	txt  map[string][]string
	addr map[string][]string
}

func newFakeDNS() *fakeDNS {
	return &fakeDNS{txt: map[string][]string{}, addr: map[string][]string{}}
}

func (f *fakeDNS) set(name string, vals ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.txt[name] = vals
}

func (f *fakeDNS) TXT(_ context.Context, name string) (*domains.TXTResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return &domains.TXTResult{Name: name, Zone: "acme.net", Servers: []domains.ServerAnswer{
		{Server: "198.51.100.1:53", Authoritative: true, Records: f.txt[name]},
		{Server: "198.51.100.2:53", Authoritative: true, Records: f.txt[name]}}}, nil
}

func (f *fakeDNS) Resolve(_ context.Context, host string) (*domains.Resolution, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return &domains.Resolution{Host: host, Addrs: f.addr[host]}, nil
}

func routedHosts(r *fakeRouter) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var hs []string
	for _, rt := range r.table.Routes {
		hs = append(hs, rt.Hosts...)
	}
	return hs
}

func has(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// SC-14 / Q34-Q36: fresh TXT proof, unique active ownership, tombstones.
func TestDomainClaimLifecycle(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dnsv := newFakeDNS()
	h.p.DNS = dnsv
	h.p.Node.Ingress.Mode = "direct"
	h.p.Node.Ingress.PublicIPv4 = "203.0.113.10"
	d0 := h.deploy()
	h.run(d0.ID)

	other := &store.Project{Name: "other", CloneURL: "https://140.82.112.3/o/other.git"}
	if err := h.s.CreateProject(ctx, other); err != nil {
		t.Fatal(err)
	}

	// Invalid and platform-reserved names are refused.
	for _, bad := range []string{"*.acme.net", "10.1.2.3", "localhost", "app.od.test", "evil.od.test"} {
		if _, _, err := h.p.ClaimDomain(ctx, h.prj, "", bad); err == nil {
			t.Fatalf("claim of %q accepted", bad)
		}
	}

	d, in, err := h.p.ClaimDomain(ctx, h.prj, "", "Shop.Acme.net")
	if err != nil {
		t.Fatal(err)
	}
	if d.Hostname != "shop.acme.net" || in.TXTName != "_opendeploy-challenge.shop.acme.net" || !strings.Contains(in.TXTValue, d.ClaimToken) ||
		len(in.Routing.IPs) != 1 {
		t.Fatalf("claim/instructions: %+v %+v", d, in)
	}
	// Stale A record alone (no TXT) is not proof and routes nothing.
	dnsv.addr["shop.acme.net"] = []string{"203.0.113.10"}
	if _, _, err := h.p.VerifyDomain(ctx, d.ID); !errors.Is(err, ErrNotVerified) {
		t.Fatalf("verified without TXT: %v", err)
	}
	if has(routedHosts(h.rtr), "shop.acme.net") {
		t.Fatal("unverified domain routed")
	}
	// Another instance's proof (same token, different instance) is rejected.
	dnsv.set(in.TXTName, domains.TXTValue("ins_attacker", d.ClaimToken))
	if _, _, err := h.p.VerifyDomain(ctx, d.ID); !errors.Is(err, ErrNotVerified) {
		t.Fatalf("wrong-instance proof accepted: %v", err)
	}
	// Correct proof attaches, routes and schedules the TLS check.
	dnsv.set(in.TXTName, "unrelated", in.TXTValue)
	vd, chk, err := h.p.VerifyDomain(ctx, d.ID)
	if err != nil || vd.Status != "active" || !chk.Proven || chk.Routing == nil || !chk.Routing.OK {
		t.Fatalf("verify: %v %+v %+v", err, vd, chk)
	}
	if !has(routedHosts(h.rtr), "shop.acme.net") || !has(routedHosts(h.rtr), "app.od.test") {
		t.Fatalf("route table: %v", routedHosts(h.rtr))
	}
	jobs, _ := h.s.ListJobs(ctx, "queued", 100)
	n := 0
	for _, j := range jobs {
		if j.Kind == JobDomainCheck {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("tls check jobs: %d", n)
	}

	// Q34: another project cannot claim an actively owned hostname.
	if _, _, err := h.p.ClaimDomain(ctx, other, "", "shop.acme.net"); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("second claim of active domain: %v", err)
	}

	// Q35: detach leaves a tombstone; stale A + old TXT still in DNS do not
	// let anyone (including another project) re-attach without fresh proof.
	if err := h.p.DetachDomain(ctx, vd); err != nil {
		t.Fatal(err)
	}
	if has(routedHosts(h.rtr), "shop.acme.net") {
		t.Fatal("detached domain still routed")
	}
	hist, _ := h.s.DomainHistory(ctx, "shop.acme.net")
	if len(hist) != 1 || hist[0].Status != "tombstoned" || hist[0].TombstonedAt == "" {
		t.Fatalf("tombstone: %+v", hist)
	}
	d2, in2, err := h.p.ClaimDomain(ctx, other, "", "shop.acme.net")
	if err != nil {
		t.Fatal(err)
	}
	if in2.TXTValue == in.TXTValue {
		t.Fatal("re-claim reused the old token")
	}
	if _, _, err := h.p.VerifyDomain(ctx, d2.ID); !errors.Is(err, ErrNotVerified) {
		t.Fatalf("re-claim accepted with stale proof: %v", err)
	}
	if has(routedHosts(h.rtr), "shop.acme.net") {
		t.Fatal("stale DNS routed to the new claimant")
	}

	// A newer claim supersedes an older pending one: the older token is dead.
	d3, in3, err := h.p.ClaimDomain(ctx, h.prj, "", "shop.acme.net")
	if err != nil {
		t.Fatal(err)
	}
	dnsv.set(in.TXTName, in2.TXTValue)
	if _, _, err := h.p.VerifyDomain(ctx, d2.ID); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("superseded claim verified: %v", err)
	}
	// Expired claims are refused even with the right record published.
	dnsv.set(in.TXTName, in3.TXTValue)
	if err := h.s.DB.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE domains SET claim_expires_at='2000-01-01T00:00:00.000000000Z' WHERE id=?`, d3.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.p.VerifyDomain(ctx, d3.ID); !errors.Is(err, ErrClaimExpired) {
		t.Fatalf("expired claim: %v", err)
	}
	if g, _ := h.s.GetDomain(ctx, d3.ID); g.Status != "expired" || g.ClaimToken != "" {
		t.Fatalf("expired claim not retired: %+v", g)
	}
}

func selfSigned(t *testing.T, host string, notAfter time.Time) *x509.Certificate {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: host}, Issuer: pkix.Name{CommonName: "Test CA"},
		DNSNames: []string{host}, NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func TestDomainTLSCheck(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dnsv := newFakeDNS()
	h.p.DNS = dnsv
	h.p.Node.Ingress.Mode = "direct"
	d, in, err := h.p.ClaimDomain(ctx, h.prj, "", "www.acme.net")
	if err != nil {
		t.Fatal(err)
	}
	dnsv.set(in.TXTName, in.TXTValue)
	if _, _, err := h.p.VerifyDomain(ctx, d.ID); err != nil {
		t.Fatal(err)
	}
	var probe struct {
		cert    *x509.Certificate
		trusted bool
		err     error
	}
	h.p.TLSProbe = func(context.Context, string) (*x509.Certificate, bool, error) {
		return probe.cert, probe.trusted, probe.err
	}
	job := &store.Job{Attempts: 1, MaxAttempts: 3}
	tlsStatus := func() string { g, _ := h.s.GetDomain(ctx, d.ID); return g.TLSStatus }

	probe.err = errors.New("connection refused")
	if err := h.p.checkDomainTLS(ctx, job, d.ID); !errors.Is(err, ErrRetry) || tlsStatus() != "issuing" {
		t.Fatalf("issuing: %v %s", err, tlsStatus())
	}
	probe.err, probe.cert, probe.trusted = nil, selfSigned(t, "other.acme.net", time.Now().Add(90*24*time.Hour)), true
	if err := h.p.checkDomainTLS(ctx, job, d.ID); !errors.Is(err, ErrRetry) {
		t.Fatalf("wrong-name certificate accepted: %v", err)
	}
	probe.cert, probe.trusted = selfSigned(t, "www.acme.net", time.Now().Add(90*24*time.Hour)), false
	if err := h.p.checkDomainTLS(ctx, job, d.ID); !errors.Is(err, ErrRetry) {
		t.Fatalf("untrusted certificate accepted: %v", err)
	}
	job.Attempts = 3
	_ = h.p.checkDomainTLS(ctx, job, d.ID)
	if tlsStatus() != "error" {
		t.Fatalf("exhausted attempts: %s", tlsStatus())
	}
	probe.trusted = true
	if err := h.p.checkDomainTLS(ctx, job, d.ID); err != nil || tlsStatus() != "active" {
		t.Fatalf("valid certificate: %v %s", err, tlsStatus())
	}
	// LAN mode never probes public TLS.
	h.p.Node.Ingress.Mode = "lan"
	probe.err = errors.New("must not be called")
	if err := h.p.checkDomainTLS(ctx, job, d.ID); err != nil {
		t.Fatal(err)
	}
}
