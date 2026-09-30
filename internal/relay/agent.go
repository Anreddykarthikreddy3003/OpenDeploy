package relay

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
)

// AgentConfig configures a relay agent.
type AgentConfig struct {
	ServerAddr  string // relay tunnel endpoint host:port
	ServerName  string // expected tunnel certificate name (default: host of ServerAddr)
	StateDir    string // agent.key, agent.crt, ca.crt (0600, agent identity only)
	EnrollToken string // one-time token (only needed until enrolled)
	LocalHTTPS  string // local edge TLS address, e.g. 127.0.0.1:443
	LocalHTTP   string // local edge HTTP address, e.g. 127.0.0.1:80
	// Hosts returns the hostnames the local edge currently serves.
	Hosts        func(ctx context.Context) ([]string, error)
	SyncInterval time.Duration // default 10s
	MaxStreams   int           // default 2048
	Log          *slog.Logger
}

// Agent maintains the outbound tunnel.
type Agent struct {
	cfg AgentConfig
	log *slog.Logger

	mu       sync.Mutex
	cert     *tls.Certificate
	leaf     *x509.Certificate
	ca       *x509.CertPool
	id       Identity
	accepted []string
	rejected map[string]string
	hostSet  map[string]bool
	up       bool
}

// NewAgent creates an agent.
func NewAgent(cfg AgentConfig) *Agent {
	if cfg.SyncInterval <= 0 {
		cfg.SyncInterval = 10 * time.Second
	}
	if cfg.MaxStreams <= 0 {
		cfg.MaxStreams = 2048
	}
	if cfg.ServerName == "" {
		cfg.ServerName, _, _ = net.SplitHostPort(cfg.ServerAddr)
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &Agent{cfg: cfg, log: cfg.Log, hostSet: map[string]bool{}}
}

// Status is the agent's view for operators and the dashboard.
type Status struct {
	Connected bool              `json:"connected"`
	Tenant    string            `json:"tenant,omitempty"`
	Instance  string            `json:"instance,omitempty"`
	CertUntil time.Time         `json:"cert_until,omitempty"`
	Accepted  []string          `json:"accepted,omitempty"`
	Rejected  map[string]string `json:"rejected,omitempty"`
}

// Status reports the current state.
func (a *Agent) Status() Status {
	a.mu.Lock()
	defer a.mu.Unlock()
	st := Status{Connected: a.up, Tenant: a.id.Tenant, Instance: a.id.Instance, Accepted: a.accepted, Rejected: a.rejected}
	if a.leaf != nil {
		st.CertUntil = a.leaf.NotAfter
	}
	return st
}

func (a *Agent) paths() (key, crt, ca string) {
	return filepath.Join(a.cfg.StateDir, "agent.key"), filepath.Join(a.cfg.StateDir, "agent.crt"), filepath.Join(a.cfg.StateDir, "ca.crt")
}

func (a *Agent) loadCredentials() error {
	kp, cp, cap := a.paths()
	cert, err := tls.LoadX509KeyPair(cp, kp)
	if err != nil {
		return err
	}
	caPEM, err := os.ReadFile(cap)
	if err != nil {
		return err
	}
	caCert, err := ParseCertPEM(caPEM)
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return err
	}
	id, err := IdentityFromCert(leaf)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	a.mu.Lock()
	a.cert, a.leaf, a.ca, a.id = &cert, leaf, pool, id
	a.mu.Unlock()
	return nil
}

func (a *Agent) storeCredentials(key *ecdsa.PrivateKey, certPEM, caPEM []byte) error {
	kp, cp, cap := a.paths()
	if caPEM != nil {
		if err := writeFileAtomic(cap, caPEM, 0o600); err != nil {
			return err
		}
	}
	if err := writeFileAtomic(kp, EncodeKey(key), 0o600); err != nil {
		return err
	}
	if err := writeFileAtomic(cp, certPEM, 0o600); err != nil {
		return err
	}
	return a.loadCredentials()
}

// Enroll redeems the one-time token. The relay's certificate chain must
// contain the CA pinned by the token, so a network attacker cannot
// substitute its own relay during enrollment.
func (a *Agent) Enroll(ctx context.Context) error {
	tok, err := ParseEnrollToken(a.cfg.EnrollToken)
	if err != nil {
		return err
	}
	var pinned *x509.Certificate
	tlsc := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{ALPNEnroll}, ServerName: a.cfg.ServerName,
		InsecureSkipVerify: true, //nolint:gosec // verified against the pinned CA below
		VerifyConnection: func(cs tls.ConnectionState) error {
			for _, c := range cs.PeerCertificates {
				if fp := sha256.Sum256(c.Raw); hex.EncodeToString(fp[:]) == tok.CAFingerprint {
					pinned = c
				}
			}
			if pinned == nil || len(cs.PeerCertificates) == 0 {
				return errors.New("relay does not present the CA pinned by the enrollment token")
			}
			pool := x509.NewCertPool()
			pool.AddCert(pinned)
			_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: pool, DNSName: a.cfg.ServerName})
			return err
		}}
	key, csr, err := NewCSR()
	if err != nil {
		return err
	}
	body, _ := json.Marshal(EnrollRequest{Token: tok.String(), CSR: string(csr)})
	hc := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: tlsc, ForceAttemptHTTP2: false}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+a.cfg.ServerAddr+"/v1/enroll", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	res, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 512))
		return fmt.Errorf("enrollment refused: %s %s", res.Status, strings.TrimSpace(string(b)))
	}
	var er EnrollResponse
	if err := json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&er); err != nil {
		return err
	}
	caCert, err := ParseCertPEM([]byte(er.CA))
	if err != nil || !caCert.Equal(pinned) {
		return errors.New("enrollment response CA does not match the pinned CA")
	}
	a.log.Info("enrolled with relay", "tenant", er.Tenant, "instance", er.Instance)
	return a.storeCredentials(key, []byte(er.Cert), []byte(er.CA))
}

// Run keeps the tunnel up until ctx ends.
func (a *Agent) Run(ctx context.Context) error {
	if err := a.loadCredentials(); err != nil {
		if a.cfg.EnrollToken == "" {
			return fmt.Errorf("relay agent not enrolled and no enrollment token: %w", err)
		}
		if err := a.Enroll(ctx); err != nil {
			return err
		}
	}
	backoff := time.Second
	for ctx.Err() == nil {
		start := time.Now()
		err := a.session(ctx)
		a.mu.Lock()
		a.up = false
		a.mu.Unlock()
		if ctx.Err() != nil {
			return nil
		}
		if time.Since(start) > time.Minute {
			backoff = time.Second
		}
		a.log.Warn("relay tunnel down; reconnecting", "err", err, "in", backoff)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		if backoff < time.Minute {
			backoff *= 2
		}
	}
	return nil
}

func (a *Agent) dial(ctx context.Context) (*tls.Conn, error) {
	a.mu.Lock()
	pool := a.ca
	a.mu.Unlock()
	tlsc := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: a.cfg.ServerName, NextProtos: []string{ALPNTunnel},
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			a.mu.Lock()
			defer a.mu.Unlock()
			return a.cert, nil
		}}
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}, Config: tlsc}
	c, err := d.DialContext(ctx, "tcp", a.cfg.ServerAddr)
	if err != nil {
		return nil, err
	}
	tc := c.(*tls.Conn)
	if tc.ConnectionState().NegotiatedProtocol != ALPNTunnel {
		tc.Close()
		return nil, errors.New("relay did not negotiate the tunnel protocol")
	}
	return tc, nil
}

func (a *Agent) session(ctx context.Context) error {
	tc, err := a.dial(ctx)
	if err != nil {
		return err
	}
	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive, cfg.KeepAliveInterval = true, 15*time.Second
	cfg.ConnectionWriteTimeout = 15 * time.Second
	cfg.LogOutput = io.Discard
	ys, err := yamux.Client(tc, cfg)
	if err != nil {
		tc.Close()
		return err
	}
	defer ys.Close()
	ctrl, err := ys.OpenStream()
	if err != nil {
		return err
	}
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wmu sync.Mutex
	send := func(m ControlMsg) error {
		wmu.Lock()
		defer wmu.Unlock()
		_ = ctrl.SetWriteDeadline(time.Now().Add(10 * time.Second))
		return writeLine(ctrl, m)
	}
	// Control replies.
	renewKey := make(chan *ecdsa.PrivateKey, 1)
	errc := make(chan error, 3)
	go func() {
		lr := newLineReader(ctrl)
		for {
			var m ControlMsg
			if err := lr.next(&m); err != nil {
				errc <- fmt.Errorf("control stream: %w", err)
				return
			}
			switch m.Type {
			case MsgRoutesAck:
				a.mu.Lock()
				a.accepted, a.rejected, a.up = m.Accepted, m.Rejected, true
				a.mu.Unlock()
				for h, why := range m.Rejected {
					a.log.Warn("relay refused route", "host", h, "reason", why)
				}
			case MsgRenewed:
				select {
				case k := <-renewKey:
					if err := a.storeCredentials(k, []byte(m.Cert), nil); err != nil {
						a.log.Error("store renewed relay credential", "err", err)
					} else {
						a.log.Info("relay credential renewed")
					}
				default:
				}
			case MsgError:
				a.log.Warn("relay error", "message", m.Message)
			}
		}
	}()
	// Route sync + renewal.
	go func() {
		t := time.NewTicker(a.cfg.SyncInterval)
		defer t.Stop()
		var last string
		for {
			hosts, err := a.cfg.Hosts(sctx)
			if err == nil {
				sort.Strings(hosts)
				if key := strings.Join(hosts, ","); key != last {
					if err := send(ControlMsg{Type: MsgRoutes, Hosts: hosts}); err != nil {
						errc <- err
						return
					}
					last = key
					set := map[string]bool{}
					for _, h := range hosts {
						set[h] = true
					}
					a.mu.Lock()
					a.hostSet = set
					a.mu.Unlock()
				}
			} else {
				a.log.Warn("reading local routes", "err", err)
			}
			a.mu.Lock()
			leaf := a.leaf
			a.mu.Unlock()
			if life := leaf.NotAfter.Sub(leaf.NotBefore); time.Until(leaf.NotAfter) < life/3 && len(renewKey) == 0 {
				if k, csr, err := NewCSR(); err == nil {
					renewKey <- k
					if err := send(ControlMsg{Type: MsgRenew, CSR: string(csr)}); err != nil {
						errc <- err
						return
					}
				}
			}
			select {
			case <-sctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	// Data streams.
	sem := make(chan struct{}, a.cfg.MaxStreams)
	go func() {
		for {
			st, err := ys.AcceptStream()
			if err != nil {
				errc <- err
				return
			}
			select {
			case sem <- struct{}{}:
				go func() {
					defer func() { <-sem }()
					a.handleStream(st)
				}()
			default:
				st.Close()
			}
		}
	}()
	select {
	case <-ctx.Done():
		return nil
	case err := <-errc:
		return err
	}
}

func (a *Agent) handleStream(st net.Conn) {
	defer st.Close()
	_ = st.SetReadDeadline(time.Now().Add(15 * time.Second))
	lr := newLineReader(st)
	var h StreamHeader
	if err := lr.next(&h); err != nil || h.V != 1 {
		return
	}
	_ = st.SetReadDeadline(time.Time{})
	a.mu.Lock()
	known := a.hostSet[h.Host]
	a.mu.Unlock()
	target := a.cfg.LocalHTTPS
	if h.Kind == "http" {
		target = a.cfg.LocalHTTP
	}
	if !known || target == "" {
		return // defence in depth: never forward hosts this node does not serve
	}
	up, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}
	defer up.Close()
	client := &prefixConn{Conn: st, r: lr.r}
	sent := make(chan struct{})
	go func() {
		_, _ = io.Copy(up, client)
		if cw, ok := up.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		close(sent)
	}()
	_, _ = io.Copy(st, up)
	_ = st.Close()
	_ = up.Close()
	<-sent
}

// PEMCert is a helper for tests and tooling.
func PEMCert(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}
