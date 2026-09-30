package domains

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestNormalize(t *testing.T) {
	ok := map[string]string{
		"Shop.Example.COM.": "shop.example.com",
		"bücher.de":         "xn--bcher-kva.de",
		"a-b.c-d.io":        "a-b.c-d.io",
	}
	for in, want := range ok {
		got, err := Normalize(in)
		if err != nil || got != want {
			t.Errorf("Normalize(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "*.example.com", "10.0.0.1", "[::1]", "localhost", "app.localhost", "printer.local", "x.internal",
		"com", "-a.example.com", "a_b.example.com", "_opendeploy-challenge.example.com", "a..b.com", "a.123", strings.Repeat("a", 64) + ".com"} {
		if _, err := Normalize(bad); !errors.Is(err, ErrInvalidHostname) {
			t.Errorf("Normalize(%q) accepted: %v", bad, err)
		}
	}
	if !Within("a.apps.example.com", "apps.example.com") || !Within("apps.example.com", "apps.example.com.") || Within("xapps.example.com", "apps.example.com") {
		t.Fatal("Within")
	}
}

func TestTokens(t *testing.T) {
	a, b := NewToken(), NewToken()
	if a == b || len(a) != 32 {
		t.Fatalf("tokens %q %q", a, b)
	}
	if TXTValue("ins_1", a) == TXTValue("ins_2", a) {
		t.Fatal("TXT value must bind the instance")
	}
}

// zoneServer is a tiny DNS server acting as both the recursive resolver and
// the two authoritative servers (127.0.0.1 and 127.0.0.2) of test zones.
type zoneServer struct {
	mu      sync.Mutex
	records map[string][]dns.RR // key: lower(fqdn)/type
	perNS   map[string]map[string][]dns.RR
	noAA    bool
	port    string
}

func (z *zoneServer) add(server string, rrs ...string) {
	z.mu.Lock()
	defer z.mu.Unlock()
	for _, s := range rrs {
		rr, err := dns.NewRR(s)
		if err != nil {
			panic(err)
		}
		k := strings.ToLower(rr.Header().Name) + "/" + dns.TypeToString[rr.Header().Rrtype]
		if server == "" {
			z.records[k] = append(z.records[k], rr)
		} else {
			if z.perNS[server] == nil {
				z.perNS[server] = map[string][]dns.RR{}
			}
			z.perNS[server][k] = append(z.perNS[server][k], rr)
		}
	}
}

func (z *zoneServer) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	z.mu.Lock()
	defer z.mu.Unlock()
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = !z.noAA || req.RecursionDesired
	q := req.Question[0]
	host, _, _ := net.SplitHostPort(w.LocalAddr().String())
	lookup := func(name string, qt uint16) []dns.RR {
		k := strings.ToLower(name) + "/" + dns.TypeToString[qt]
		if !req.RecursionDesired {
			if per, ok := z.perNS[host]; ok {
				if rr, ok := per[k]; ok {
					return rr
				}
			}
		}
		return z.records[k]
	}
	name := q.Name
	for i := 0; i < 8; i++ {
		if rr := lookup(name, q.Qtype); len(rr) > 0 {
			m.Answer = append(m.Answer, rr...)
			break
		}
		c := lookup(name, dns.TypeCNAME)
		if len(c) == 0 {
			break
		}
		m.Answer = append(m.Answer, c...)
		if !req.RecursionDesired {
			break // authoritative servers do not chase out-of-zone CNAMEs
		}
		name = c[0].(*dns.CNAME).Target
	}
	_ = w.WriteMsg(m)
}

func startZone(t *testing.T) (*zoneServer, *Resolver) {
	t.Helper()
	z := &zoneServer{records: map[string][]dns.RR{}, perNS: map[string]map[string][]dns.RR{}}
	pc1, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(pc1.LocalAddr().String())
	pc2, err := net.ListenPacket("udp", "127.0.0.2:"+port)
	if err != nil {
		pc1.Close()
		t.Skipf("second loopback address unavailable: %v", err)
	}
	for _, pc := range []net.PacketConn{pc1, pc2} {
		srv := &dns.Server{PacketConn: pc, Handler: z}
		go srv.ActivateAndServe()
		t.Cleanup(func() { srv.Shutdown() })
	}
	z.port = port
	z.add("", "acme-shop.net. 60 IN NS ns1.acme-shop.net.", "acme-shop.net. 60 IN NS ns2.acme-shop.net.",
		"ns1.acme-shop.net. 60 IN A 127.0.0.1", "ns2.acme-shop.net. 60 IN A 127.0.0.2",
		// delegated child zone served only by ns2
		"dev.acme-shop.net. 60 IN NS ns2.acme-shop.net.")
	r := &Resolver{Recursive: []string{"127.0.0.1:" + port}, Port: port, Timeout: time.Second, AllowPrivateNS: true}
	return z, r
}

func TestAuthoritativeTXT(t *testing.T) {
	z, r := startZone(t)
	ctx := context.Background()
	tok := NewToken()
	want := TXTValue("ins_a", tok)
	name := ChallengeName("www.acme-shop.net")

	if zone, err := r.FindZone(ctx, name); err != nil || zone != "acme-shop.net." {
		t.Fatalf("zone %q %v", zone, err)
	}
	if zone, err := r.FindZone(ctx, "_opendeploy-challenge.api.dev.acme-shop.net"); err != nil || zone != "dev.acme-shop.net." {
		t.Fatalf("child zone %q %v", zone, err)
	}

	// Missing record.
	res, err := r.TXT(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := res.Proves(want); ok {
		t.Fatal("proved without a record")
	}
	// Only one of two authoritative servers has it (propagation).
	z.add("127.0.0.1", name+`. 60 IN TXT "`+want+`"`)
	res, _ = r.TXT(ctx, name)
	if ok, why := res.Proves(want); ok || !strings.Contains(why, "1 of 2") {
		t.Fatalf("partial propagation accepted: %v %s", ok, why)
	}
	// Both have it, plus an unrelated record.
	z.add("127.0.0.2", name+`. 60 IN TXT "`+want+`"`, name+`. 60 IN TXT "google-site-verification=x"`)
	res, _ = r.TXT(ctx, name)
	if ok, why := res.Proves(want); !ok {
		t.Fatalf("valid proof rejected: %s %+v", why, res)
	}
	// Replayed/old token or another instance's value is not proof.
	if ok, _ := res.Proves(TXTValue("ins_a", NewToken())); ok {
		t.Fatal("different token accepted")
	}
	if ok, _ := res.Proves(TXTValue("ins_b", tok)); ok {
		t.Fatal("wrong-instance value accepted")
	}
	// Non-authoritative answers (e.g. a lame or caching server) never prove.
	z.mu.Lock()
	z.noAA = true
	z.mu.Unlock()
	res, _ = r.TXT(ctx, name)
	if ok, why := res.Proves(want); ok || !strings.Contains(why, "no authoritative") {
		t.Fatalf("non-authoritative answer accepted: %s", why)
	}
	z.mu.Lock()
	z.noAA = false
	z.mu.Unlock()

	// A challenge CNAME pointing at another zone is not followed.
	cn := ChallengeName("shop.acme-shop.net")
	z.add("", cn+". 60 IN CNAME proof.attacker-zone.net.", "attacker-zone.net. 60 IN NS ns1.acme-shop.net.",
		`proof.attacker-zone.net. 60 IN TXT "`+want+`"`)
	res, _ = r.TXT(ctx, cn)
	if ok, _ := res.Proves(want); ok {
		t.Fatal("CNAME-delegated challenge accepted")
	}

	// Private authoritative servers are refused unless allowed.
	strict := *r
	strict.AllowPrivateNS = false
	if _, err := strict.TXT(ctx, name); err == nil || !strings.Contains(err.Error(), "no usable authoritative") {
		t.Fatalf("private NS used: %v", err)
	}
}

func TestCheckRouting(t *testing.T) {
	z, r := startZone(t)
	ctx := context.Background()
	z.add("", "www.acme-shop.net. 60 IN CNAME edge.acme-shop.net.", "edge.acme-shop.net. 60 IN A 203.0.113.10",
		"relay.opendeploy-relay.net. 60 IN A 203.0.113.10", "other.acme-shop.net. 60 IN A 203.0.113.10", "other.acme-shop.net. 60 IN A 198.51.100.7")
	if rc := CheckRouting(ctx, r, "www.acme-shop.net", Targets{IPs: []string{"203.0.113.10"}}); !rc.OK || len(rc.CNAMEs) != 1 {
		t.Fatalf("direct: %+v", rc)
	}
	if rc := CheckRouting(ctx, r, "www.acme-shop.net", Targets{Hosts: []string{"relay.opendeploy-relay.net"}}); !rc.OK {
		t.Fatalf("relay: %+v", rc)
	}
	if rc := CheckRouting(ctx, r, "other.acme-shop.net", Targets{IPs: []string{"203.0.113.10"}}); rc.OK || !strings.Contains(rc.Detail, "198.51.100.7") {
		t.Fatalf("stray address accepted: %+v", rc)
	}
	if rc := CheckRouting(ctx, r, "missing.acme-shop.net", Targets{IPs: []string{"203.0.113.10"}}); rc.OK {
		t.Fatalf("missing accepted: %+v", rc)
	}
	if rc := CheckRouting(ctx, r, "www.acme-shop.net", Targets{}); rc.OK || !strings.Contains(rc.Detail, "unknown") {
		t.Fatalf("empty targets: %+v", rc)
	}
	if !publicIP(net.ParseIP("8.8.8.8")) || publicIP(net.ParseIP("100.64.1.1")) || publicIP(net.ParseIP("169.254.169.254")) || publicIP(net.ParseIP("fd00::1")) {
		t.Fatal("publicIP")
	}
}
