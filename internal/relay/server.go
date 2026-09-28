package relay

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/domains"
)

// ServerConfig configures a relay server.
type ServerConfig struct {
	DataDir      string   // CA, registry, audit log
	TunnelNames  []string // DNS names agents use to reach the tunnel endpoint
	PublicSuffix string   // instances own <instance>.<suffix>
	DNS          domains.Verifier
	Log          *slog.Logger

	MaxStreamsPerInstance int           // default 1024
	MaxConnsPerIP         int           // default 256
	PeekTimeout           time.Duration // default 10s
	ProofRecheck          time.Duration // custom-domain proof re-verification (default 1h)
	AuthRecheck           time.Duration // revocation/expiry re-check of live tunnels (default 5s)
	EnrollPerMinute       int           // per source IP (default 10)
	CertTTL               time.Duration // agent credential lifetime (default/max 24h)
	AuditPath             string        // default <DataDir>/audit.log; "-" = memory
}

// Server is the public relay.
type Server struct {
	cfg   ServerConfig
	CA    *CA
	Reg   *Registry
	Audit *Auditor
	log   *slog.Logger
	tlsc  *tls.Config

	mu       sync.RWMutex
	sessions map[string]*session // by instance
	routes   map[string]*route   // by host

	ipMu    sync.Mutex
	ipConns map[string]int
	enrolls map[string][]time.Time

	// tap observes bytes the relay forwards (tests: prove the relay only
	// ever handles ciphertext).
	tap func(host string, fromClient bool, p []byte)

	closing chan struct{}
	wg      sync.WaitGroup
	connMu  sync.Mutex
	conns   map[net.Conn]struct{}
	lns     []net.Listener
	lnMu    sync.Mutex
}

type route struct {
	host     string
	sess     *session
	custom   bool
	provedAt time.Time
}

type session struct {
	id       Identity
	ys       *yamux.Session
	ctrl     net.Conn
	wmu      sync.Mutex
	notAfter atomic.Int64
	streams  chan struct{}
	remote   string
	fp       string // current credential fingerprint
}

func (s *session) send(m ControlMsg) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	_ = s.ctrl.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return writeLine(s.ctrl, m)
}

// NewServer loads (or creates) the CA and registry.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.PublicSuffix == "" || len(cfg.TunnelNames) == 0 {
		return nil, errors.New("relay: public suffix and tunnel names are required")
	}
	cfg.PublicSuffix = strings.ToLower(strings.Trim(cfg.PublicSuffix, "."))
	def := func(v *int, d int) {
		if *v <= 0 {
			*v = d
		}
	}
	def(&cfg.MaxStreamsPerInstance, 1024)
	def(&cfg.MaxConnsPerIP, 256)
	def(&cfg.EnrollPerMinute, 10)
	if cfg.PeekTimeout <= 0 {
		cfg.PeekTimeout = 10 * time.Second
	}
	if cfg.ProofRecheck <= 0 {
		cfg.ProofRecheck = time.Hour
	}
	if cfg.CertTTL <= 0 || cfg.CertTTL > AgentCertTTL {
		cfg.CertTTL = AgentCertTTL
	}
	if cfg.AuthRecheck <= 0 {
		cfg.AuthRecheck = 5 * time.Second
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.DNS == nil {
		cfg.DNS = domains.NewResolver("1.1.1.1:53,8.8.8.8:53")
	}
	ca, err := LoadOrCreateCA(filepath.Join(cfg.DataDir, "ca"))
	if err != nil {
		return nil, err
	}
	reg, err := OpenRegistry(filepath.Join(cfg.DataDir, "registry.json"))
	if err != nil {
		return nil, err
	}
	ap := cfg.AuditPath
	if ap == "" {
		ap = filepath.Join(cfg.DataDir, "audit.log")
	} else if ap == "-" {
		ap = ""
	}
	aud, err := OpenAuditor(ap)
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	certPEM, err := ca.IssueServer(cfg.TunnelNames, key)
	if err != nil {
		return nil, err
	}
	leaf, _ := ParseCertPEM(certPEM)
	s := &Server{cfg: cfg, CA: ca, Reg: reg, Audit: aud, log: cfg.Log, sessions: map[string]*session{}, routes: map[string]*route{},
		ipConns: map[string]int{}, enrolls: map[string][]time.Time{}, closing: make(chan struct{}), conns: map[net.Conn]struct{}{}}
	s.tlsc = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.Raw, ca.Cert.Raw}, PrivateKey: key, Leaf: leaf}},
		ClientCAs:    ca.Pool(),
		ClientAuth:   tls.VerifyClientCertIfGiven,
		NextProtos:   []string{ALPNTunnel, ALPNEnroll},
	}
	return s, nil
}

// InstanceZone is the generated namespace owned by an instance.
func (s *Server) InstanceZone(instance string) string { return instance + "." + s.cfg.PublicSuffix }

// ServeTunnel accepts agent connections (enrollment and tunnels).
func (s *Server) ServeTunnel(ln net.Listener) error {
	s.track(ln)
	return s.acceptLoop(ln, func(c net.Conn) {
		tc := tls.Server(c, s.tlsc)
		_ = tc.SetDeadline(time.Now().Add(15 * time.Second))
		if err := tc.Handshake(); err != nil {
			tc.Close()
			return
		}
		_ = tc.SetDeadline(time.Time{})
		switch tc.ConnectionState().NegotiatedProtocol {
		case ALPNTunnel:
			s.handleTunnel(tc)
		case ALPNEnroll:
			s.serveEnroll(tc)
		default:
			tc.Close()
		}
	})
}

// ServeHTTPS routes public TLS connections by SNI without terminating TLS.
func (s *Server) ServeHTTPS(ln net.Listener) error {
	s.track(ln)
	return s.acceptLoop(ln, func(c net.Conn) { s.forward(c, "tls") })
}

// ServeHTTP routes public plaintext HTTP (redirects, ACME HTTP-01) by Host.
func (s *Server) ServeHTTP(ln net.Listener) error {
	s.track(ln)
	return s.acceptLoop(ln, func(c net.Conn) { s.forward(c, "http") })
}

func (s *Server) track(ln net.Listener) {
	s.lnMu.Lock()
	s.lns = append(s.lns, ln)
	s.lnMu.Unlock()
}

func (s *Server) acceptLoop(ln net.Listener, h func(net.Conn)) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-s.closing:
				return nil
			default:
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return err
		}
		s.connMu.Lock()
		s.conns[c] = struct{}{}
		s.connMu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() {
				s.connMu.Lock()
				delete(s.conns, c)
				s.connMu.Unlock()
				c.Close()
			}()
			h(c)
		}()
	}
}

// Run performs periodic re-authorisation until ctx ends.
func (s *Server) Run(ctx context.Context) {
	auth := time.NewTicker(s.cfg.AuthRecheck)
	defer auth.Stop()
	proof := time.NewTicker(s.cfg.ProofRecheck)
	defer proof.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.closing:
			return
		case <-auth.C:
			s.recheckSessions()
		case <-proof.C:
			s.recheckProofs(ctx)
		}
	}
}

// Close stops listeners and tunnels.
func (s *Server) Close() error {
	select {
	case <-s.closing:
		return nil
	default:
	}
	close(s.closing)
	s.lnMu.Lock()
	for _, ln := range s.lns {
		ln.Close()
	}
	s.lnMu.Unlock()
	s.mu.Lock()
	for _, ss := range s.sessions {
		ss.ys.Close()
	}
	s.mu.Unlock()
	s.connMu.Lock()
	for c := range s.conns {
		c.Close()
	}
	s.connMu.Unlock()
	s.wg.Wait()
	return s.Audit.Close()
}

func sourceIP(a net.Addr) string {
	if h, _, err := net.SplitHostPort(a.String()); err == nil {
		return h
	}
	return a.String()
}

// ---- enrollment ------------------------------------------------------------

func (s *Server) enrollAllowed(ip string) bool {
	s.ipMu.Lock()
	defer s.ipMu.Unlock()
	now := time.Now()
	var keep []time.Time
	for _, t := range s.enrolls[ip] {
		if now.Sub(t) < time.Minute {
			keep = append(keep, t)
		}
	}
	if len(keep) >= s.cfg.EnrollPerMinute {
		s.enrolls[ip] = keep
		return false
	}
	s.enrolls[ip] = append(keep, now)
	return true
}

// serveEnroll answers exactly one HTTP/1.1 enrollment request.
func (s *Server) serveEnroll(tc *tls.Conn) {
	defer tc.Close()
	_ = tc.SetDeadline(time.Now().Add(30 * time.Second))
	req, err := http.ReadRequest(bufio.NewReaderSize(io.LimitReader(tc, 128<<10), 4096))
	status, ctype, body := http.StatusBadRequest, "text/plain", []byte("bad request\n")
	if err == nil {
		status, ctype, body = s.enroll(req, sourceIP(tc.RemoteAddr()))
	}
	res := &http.Response{StatusCode: status, ProtoMajor: 1, ProtoMinor: 1, Header: http.Header{"Content-Type": {ctype}},
		ContentLength: int64(len(body)), Body: io.NopCloser(bytes.NewReader(body)), Close: true}
	_ = res.Write(tc)
}

func (s *Server) enroll(r *http.Request, src string) (int, string, []byte) {
	deny := func(code int, msg string) (int, string, []byte) { return code, "text/plain", []byte(msg + "\n") }
	if r.Method != http.MethodPost || r.URL.Path != "/v1/enroll" {
		return deny(http.StatusNotFound, "not found")
	}
	if !s.enrollAllowed(src) {
		s.Audit.Log(AuditRecord{Action: "enroll", Source: src, Result: "denied", Reason: "rate limited"})
		return deny(http.StatusTooManyRequests, "too many enrollment attempts")
	}
	var req EnrollRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
		return deny(http.StatusBadRequest, "bad request")
	}
	tok, err := ParseEnrollToken(req.Token)
	if err == nil && tok.CAFingerprint != s.CA.Fingerprint() {
		err = errors.New("token was issued by a different relay")
	}
	var id Identity
	if err == nil {
		id, err = s.Reg.Redeem(tok)
	}
	var certPEM []byte
	if err == nil {
		certPEM, _, err = s.CA.IssueAgent(id, []byte(req.CSR), s.cfg.CertTTL)
	}
	if err != nil {
		s.Audit.Log(AuditRecord{Action: "enroll", Tenant: id.Tenant, Instance: id.Instance, Source: src, Result: "denied", Reason: err.Error()})
		return deny(http.StatusForbidden, "enrollment refused")
	}
	// A re-enrollment rotates the credential: close tunnels using old certs.
	s.dropSession(id.Instance, "credential rotated")
	s.Audit.Log(AuditRecord{Action: "enroll", Tenant: id.Tenant, Instance: id.Instance, Source: src, Result: "success"})
	b, _ := json.Marshal(EnrollResponse{Tenant: id.Tenant, Instance: id.Instance, Cert: string(certPEM), CA: string(s.CA.PEM)})
	return http.StatusOK, "application/json", b
}

// ---- tunnels ---------------------------------------------------------------

func certFP(c *x509.Certificate) string {
	h := sha256.Sum256(c.Raw)
	return hex.EncodeToString(h[:8])
}

func (s *Server) handleTunnel(tc *tls.Conn) {
	src := sourceIP(tc.RemoteAddr())
	st := tc.ConnectionState()
	if len(st.VerifiedChains) == 0 || len(st.PeerCertificates) == 0 {
		s.Audit.Log(AuditRecord{Action: "tunnel.auth", Source: src, Result: "denied", Reason: "no verified client certificate"})
		tc.Close()
		return
	}
	leaf := st.PeerCertificates[0]
	id, err := s.Reg.Authorize(leaf)
	if err != nil {
		s.Audit.Log(AuditRecord{Action: "tunnel.auth", Tenant: id.Tenant, Instance: id.Instance, Source: src, Result: "denied", Reason: err.Error()})
		tc.Close()
		return
	}
	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive, cfg.KeepAliveInterval = true, 15*time.Second
	cfg.ConnectionWriteTimeout = 15 * time.Second
	cfg.LogOutput = io.Discard
	ys, err := yamux.Server(tc, cfg)
	if err != nil {
		tc.Close()
		return
	}
	_ = tc.SetDeadline(time.Now().Add(15 * time.Second))
	ctrl, err := ys.Accept()
	_ = tc.SetDeadline(time.Time{})
	if err != nil {
		ys.Close()
		return
	}
	sess := &session{id: id, ys: ys, ctrl: ctrl, streams: make(chan struct{}, s.cfg.MaxStreamsPerInstance), remote: src, fp: certFP(leaf)}
	sess.notAfter.Store(leaf.NotAfter.Unix())
	s.mu.Lock()
	old := s.sessions[id.Instance]
	s.sessions[id.Instance] = sess
	s.mu.Unlock()
	if old != nil {
		s.removeRoutes(old)
		old.ys.Close()
	}
	s.Audit.Log(AuditRecord{Action: "tunnel.auth", Tenant: id.Tenant, Instance: id.Instance, Source: src, Result: "success"})
	s.log.Info("tunnel up", "instance", id.String(), "remote", src)
	s.controlLoop(sess)
	s.mu.Lock()
	if s.sessions[id.Instance] == sess {
		delete(s.sessions, id.Instance)
	}
	s.mu.Unlock()
	s.removeRoutes(sess)
	ys.Close()
	s.log.Info("tunnel down", "instance", id.String())
}

func (s *Server) controlLoop(sess *session) {
	lr := newLineReader(sess.ctrl)
	for {
		var m ControlMsg
		if err := lr.next(&m); err != nil {
			return
		}
		switch m.Type {
		case MsgRoutes:
			if len(m.Hosts) > 1000 {
				_ = sess.send(ControlMsg{Type: MsgError, Message: "too many hosts"})
				continue
			}
			acc, rej := s.setRoutes(context.Background(), sess, m.Hosts)
			_ = sess.send(ControlMsg{Type: MsgRoutesAck, Accepted: acc, Rejected: rej})
		case MsgRenew:
			if err := s.Reg.Check(sess.id); err != nil {
				_ = sess.send(ControlMsg{Type: MsgError, Message: "renewal refused"})
				s.Audit.Log(AuditRecord{Action: "tunnel.renew", Tenant: sess.id.Tenant, Instance: sess.id.Instance, Result: "denied", Reason: err.Error()})
				return
			}
			certPEM, cert, err := s.CA.IssueAgent(sess.id, []byte(m.CSR), s.cfg.CertTTL)
			if err != nil {
				_ = sess.send(ControlMsg{Type: MsgError, Message: "renewal refused: " + err.Error()})
				continue
			}
			sess.notAfter.Store(cert.NotAfter.Unix())
			s.Audit.Log(AuditRecord{Action: "tunnel.renew", Tenant: sess.id.Tenant, Instance: sess.id.Instance, Result: "success"})
			_ = sess.send(ControlMsg{Type: MsgRenewed, Cert: string(certPEM)})
		default:
			_ = sess.send(ControlMsg{Type: MsgError, Message: "unknown message"})
		}
	}
}

// authorizeHost decides whether instance id may receive traffic for host.
func (s *Server) authorizeHost(ctx context.Context, id Identity, host string) (custom bool, err error) {
	h, err := domains.Normalize(host)
	if err != nil || h != host {
		return false, errors.New("invalid hostname")
	}
	if domains.Within(host, s.InstanceZone(id.Instance)) {
		return false, nil
	}
	if domains.Within(host, s.cfg.PublicSuffix) {
		return false, errors.New("hostname belongs to another instance's relay namespace")
	}
	res, err := s.cfg.DNS.TXT(ctx, domains.ChallengeName(host))
	if err != nil {
		return true, fmt.Errorf("ownership lookup failed: %v", err)
	}
	prefix := domains.InstancePrefix(id.Instance)
	if ok, why := res.ProvesFunc(func(r string) bool { return strings.HasPrefix(r, prefix) }); !ok {
		return true, errors.New("no ownership record for this instance: " + why)
	}
	return true, nil
}

func (s *Server) setRoutes(ctx context.Context, sess *session, hosts []string) ([]string, map[string]string) {
	want := map[string]bool{}
	for _, h := range hosts {
		want[strings.ToLower(strings.TrimSuffix(h, "."))] = true
	}
	rej := map[string]string{}
	var acc []string
	type ok struct {
		host   string
		custom bool
	}
	var approved []ok
	for h := range want {
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		custom, err := s.authorizeHost(cctx, sess.id, h)
		cancel()
		if err != nil {
			rej[h] = err.Error()
			s.Audit.Log(AuditRecord{Action: "route.authorize", Tenant: sess.id.Tenant, Instance: sess.id.Instance, Host: h, Result: "denied", Reason: err.Error()})
			continue
		}
		approved = append(approved, ok{h, custom})
	}
	s.mu.Lock()
	if s.sessions[sess.id.Instance] != sess {
		s.mu.Unlock()
		return nil, map[string]string{"*": "session replaced"}
	}
	for h, r := range s.routes {
		if r.sess == sess && !want[h] {
			delete(s.routes, h)
		}
	}
	var granted []string
	var conflicts []string
	for _, a := range approved {
		if cur, exists := s.routes[a.host]; exists && cur.sess.id.Instance != sess.id.Instance {
			rej[a.host] = "hostname is routed to another instance"
			conflicts = append(conflicts, a.host)
			continue
		}
		s.routes[a.host] = &route{host: a.host, sess: sess, custom: a.custom, provedAt: time.Now()}
		acc = append(acc, a.host)
		granted = append(granted, a.host)
	}
	s.mu.Unlock()
	for _, h := range conflicts {
		s.Audit.Log(AuditRecord{Action: "route.authorize", Tenant: sess.id.Tenant, Instance: sess.id.Instance, Host: h, Result: "denied", Reason: rej[h]})
	}
	sort.Strings(acc)
	for _, h := range granted {
		s.Audit.Log(AuditRecord{Action: "route.authorize", Tenant: sess.id.Tenant, Instance: sess.id.Instance, Host: h, Result: "success"})
	}
	return acc, rej
}

func (s *Server) removeRoutes(sess *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for h, r := range s.routes {
		if r.sess == sess {
			delete(s.routes, h)
		}
	}
}

func (s *Server) dropSession(instance, reason string) {
	s.mu.Lock()
	sess := s.sessions[instance]
	s.mu.Unlock()
	if sess == nil {
		return
	}
	s.Audit.Log(AuditRecord{Action: "tunnel.close", Tenant: sess.id.Tenant, Instance: instance, Result: "success", Reason: reason})
	s.removeRoutes(sess)
	sess.ys.Close()
}

// recheckSessions closes tunnels whose instance was revoked or whose
// credential expired without renewal.
func (s *Server) recheckSessions() {
	s.mu.RLock()
	var all []*session
	for _, ss := range s.sessions {
		all = append(all, ss)
	}
	s.mu.RUnlock()
	insts, err := s.Reg.Instances()
	if err != nil {
		return
	}
	byID := map[string]InstanceRecord{}
	for _, in := range insts {
		byID[in.Instance] = in
	}
	for _, ss := range all {
		in, ok := byID[ss.id.Instance]
		switch {
		case !ok || in.Revoked || in.Tenant != ss.id.Tenant:
			s.dropSession(ss.id.Instance, "revoked")
		case time.Now().Unix() > ss.notAfter.Load():
			s.dropSession(ss.id.Instance, "credential expired")
		}
	}
}

// recheckProofs withdraws custom-domain routes whose ownership record was
// removed (the domain owner revoked this instance).
func (s *Server) recheckProofs(ctx context.Context) {
	s.mu.RLock()
	var rs []route
	for _, r := range s.routes {
		if r.custom {
			rs = append(rs, *r)
		}
	}
	s.mu.RUnlock()
	for _, r := range rs {
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		_, err := s.authorizeHost(cctx, r.sess.id, r.host)
		cancel()
		if err == nil {
			continue
		}
		s.mu.Lock()
		if cur := s.routes[r.host]; cur != nil && cur.sess == r.sess {
			delete(s.routes, r.host)
		}
		s.mu.Unlock()
		s.Audit.Log(AuditRecord{Action: "route.withdraw", Tenant: r.sess.id.Tenant, Instance: r.sess.id.Instance, Host: r.host, Result: "success", Reason: err.Error()})
	}
}

// ---- public forwarding ------------------------------------------------------

func (s *Server) ipAcquire(ip string) bool {
	s.ipMu.Lock()
	defer s.ipMu.Unlock()
	if s.ipConns[ip] >= s.cfg.MaxConnsPerIP {
		return false
	}
	s.ipConns[ip]++
	return true
}

func (s *Server) ipRelease(ip string) {
	s.ipMu.Lock()
	defer s.ipMu.Unlock()
	if s.ipConns[ip]--; s.ipConns[ip] <= 0 {
		delete(s.ipConns, ip)
	}
}

// Lookup returns the instance currently serving host.
func (s *Server) Lookup(host string) (Identity, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.routes[host]
	if !ok {
		return Identity{}, false
	}
	return r.sess.id, true
}

func (s *Server) forward(c net.Conn, kind string) {
	defer c.Close()
	src := c.RemoteAddr().String()
	ip := sourceIP(c.RemoteAddr())
	if !s.ipAcquire(ip) {
		return
	}
	defer s.ipRelease(ip)
	var host string
	var peeked []byte
	var err error
	if kind == "tls" {
		host, peeked, err = PeekSNI(c, s.cfg.PeekTimeout)
	} else {
		host, peeked, err = PeekHost(c, s.cfg.PeekTimeout)
	}
	if err != nil {
		return
	}
	s.mu.RLock()
	r := s.routes[host]
	s.mu.RUnlock()
	if r == nil {
		if kind == "http" {
			_, _ = io.WriteString(c, "HTTP/1.1 404 Not Found\r\nContent-Length: 13\r\nConnection: close\r\n\r\nunknown host\n")
		}
		return
	}
	sess := r.sess
	select {
	case sess.streams <- struct{}{}:
		defer func() { <-sess.streams }()
	default:
		return // instance at its stream limit
	}
	st, err := sess.ys.OpenStream()
	if err != nil {
		return
	}
	defer st.Close()
	if err := writeLine(st, StreamHeader{V: 1, Kind: kind, Host: host, Client: src}); err != nil {
		return
	}
	s.splice(withPrefix(c, peeked), st, host)
}

type tapWriter struct {
	w          io.Writer
	fn         func(string, bool, []byte)
	host       string
	fromClient bool
}

func (t tapWriter) Write(p []byte) (int, error) {
	t.fn(t.host, t.fromClient, p)
	return t.w.Write(p)
}

func (s *Server) splice(client net.Conn, backend net.Conn, host string) {
	var toBackend, toClient io.Writer = backend, client
	if s.tap != nil {
		toBackend = tapWriter{backend, s.tap, host, true}
		toClient = tapWriter{client, s.tap, host, false}
	}
	up := make(chan struct{})
	go func() {
		// Client finished sending: half-close towards the backend.
		_, _ = io.Copy(toBackend, client)
		_ = backend.Close()
		close(up)
	}()
	// Backend finished: the connection is over.
	_, _ = io.Copy(toClient, backend)
	_ = client.Close()
	_ = backend.Close()
	<-up
}
