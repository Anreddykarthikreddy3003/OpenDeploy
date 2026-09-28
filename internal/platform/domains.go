package platform

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/audit"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/domains"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/ids"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/state"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/store"
)

// Domain claim policy.
const (
	ClaimTTL             = 72 * time.Hour
	maxDomainsPerProject = 50
	tlsCheckAttempts     = 12 // ~1h of backoff before tls_status=error
)

// Domain errors surfaced to API callers.
var (
	ErrDomainReserved = errors.New("hostname is reserved for OpenDeploy")
	ErrDomainQuota    = errors.New("project domain limit reached")
	ErrClaimExpired   = errors.New("claim expired; create a new claim to get a fresh token")
	ErrNotVerified    = errors.New("ownership not proven")
)

// TLSProbe fetches the certificate the local edge serves for host.
type TLSProbe func(ctx context.Context, host string) (leaf *x509.Certificate, chainTrusted bool, err error)

// DomainInstructions tell the user exactly what to publish.
type DomainInstructions struct {
	TXTName   string          `json:"txt_name"`
	TXTValue  string          `json:"txt_value"`
	ExpiresAt string          `json:"expires_at"`
	Routing   domains.Targets `json:"routing"`
	Mode      string          `json:"ingress_mode"`
	Note      string          `json:"note,omitempty"`
}

// DomainCheck is persisted as the domain's last_check.
type DomainCheck struct {
	At        string                `json:"at"`
	Ownership string                `json:"ownership"`
	Proven    bool                  `json:"proven"`
	TXT       *domains.TXTResult    `json:"txt,omitempty"`
	Routing   *domains.RoutingCheck `json:"routing,omitempty"`
	TLS       string                `json:"tls,omitempty"`
}

// InstanceID returns this node's stable claim-binding identity.
func (p *Platform) InstanceID(ctx context.Context) (string, error) {
	if p.Node.Ingress.Relay.InstanceID != "" {
		return p.Node.Ingress.Relay.InstanceID, nil
	}
	var id string
	ok, err := p.Store.GetSetting(ctx, "instance_id", &id)
	if err != nil {
		return "", err
	}
	if ok && id != "" {
		return id, nil
	}
	id = ids.New("ins")
	return id, p.Store.SetSetting(ctx, "instance_id", id)
}

// reservedDomain reports whether host lives in a namespace OpenDeploy
// allocates itself (generated hostnames, relay suffix, the admin URL).
func (p *Platform) reservedDomain(host string) bool {
	if domains.Within(host, p.baseDomain()) || domains.Within(host, p.Node.Ingress.Relay.PublicSuffix) {
		return true
	}
	if u, err := url.Parse(p.Node.API.PublicURL); err == nil && u.Hostname() != "" && strings.EqualFold(u.Hostname(), host) {
		return true
	}
	return false
}

// routingTargets are where custom domains must point for the ingress mode.
func (p *Platform) routingTargets() domains.Targets {
	in := p.Node.Ingress
	switch in.Mode {
	case "relay":
		if in.Relay.PublicSuffix != "" {
			return domains.Targets{Hosts: []string{"edge." + strings.TrimPrefix(in.Relay.PublicSuffix, ".")}}
		}
		if h, _, err := net.SplitHostPort(in.Relay.ServerAddr); err == nil {
			return domains.Targets{Hosts: []string{h}}
		}
	case "direct":
		var t domains.Targets
		for _, ip := range []string{in.PublicIPv4, in.PublicIPv6} {
			if ip != "" {
				t.IPs = append(t.IPs, ip)
			}
		}
		return t
	}
	return domains.Targets{}
}

// ClaimDomain allocates a fresh, expiring TXT challenge for hostname on
// one of the project's environments (PRD §10.2 steps 1-3).
func (p *Platform) ClaimDomain(ctx context.Context, proj *store.Project, envName, hostname string) (*store.Domain, *DomainInstructions, error) {
	host, err := domains.Normalize(hostname)
	if err != nil {
		return nil, nil, err
	}
	if p.reservedDomain(host) {
		return nil, nil, ErrDomainReserved
	}
	if envName == "" {
		envName = "production"
	}
	env, err := p.Store.GetEnvironmentByName(ctx, proj.ID, envName)
	if err != nil {
		return nil, nil, err
	}
	if env.Status != "active" {
		return nil, nil, fmt.Errorf("%w: environment %s is not active", store.ErrConflict, env.Name)
	}
	if n, err := p.Store.CountProjectDomains(ctx, proj.ID); err != nil {
		return nil, nil, err
	} else if n >= maxDomainsPerProject {
		return nil, nil, ErrDomainQuota
	}
	inst, err := p.InstanceID(ctx)
	if err != nil {
		return nil, nil, err
	}
	d := &store.Domain{Hostname: host, ProjectID: proj.ID, EnvironmentID: env.ID, Kind: "custom", ClaimToken: domains.NewToken(),
		ClaimExpiresAt: state.FormatTime(time.Now().Add(ClaimTTL)), IngressMode: p.Node.Ingress.Mode}
	if err := p.Store.CreateDomainClaim(ctx, d); err != nil {
		return nil, nil, err
	}
	p.auditDomain(ctx, "domain.claim", d, audit.Success, "")
	return d, p.instructions(d, inst), nil
}

func (p *Platform) instructions(d *store.Domain, inst string) *DomainInstructions {
	in := &DomainInstructions{TXTName: domains.ChallengeName(d.Hostname), ExpiresAt: d.ClaimExpiresAt, Routing: p.routingTargets(), Mode: p.Node.Ingress.Mode}
	if d.ClaimToken != "" {
		in.TXTValue = domains.TXTValue(inst, d.ClaimToken)
	}
	switch {
	case p.Node.Ingress.Mode == "lan":
		in.Note = "LAN mode: the TXT proof is still required; point the name at this node on your local DNS."
	case in.Routing.Empty():
		in.Note = "Set ingress.public_ipv4/public_ipv6 so routing can be validated; ownership is proven by the TXT record alone."
	}
	return in
}

// DomainInstructions returns the current instructions for a domain.
func (p *Platform) DomainInstructions(ctx context.Context, d *store.Domain) (*DomainInstructions, error) {
	inst, err := p.InstanceID(ctx)
	if err != nil {
		return nil, err
	}
	return p.instructions(d, inst), nil
}

// VerifyDomain checks the claim against authoritative DNS (step 4),
// validates the routing path (step 5), and on proof stores unique active
// ownership and enables the route + ACME issuance (step 6).
func (p *Platform) VerifyDomain(ctx context.Context, id string) (*store.Domain, *DomainCheck, error) {
	d, err := p.Store.GetDomain(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	if d.Status != "pending" {
		return d, nil, fmt.Errorf("%w: domain is %s", store.ErrConflict, d.Status)
	}
	if d.ClaimToken == "" || !time.Now().Before(state.ParseTime(d.ClaimExpiresAt)) {
		_, _ = p.Store.ExpireDomainClaims(ctx, time.Now())
		return d, nil, ErrClaimExpired
	}
	inst, err := p.InstanceID(ctx)
	if err != nil {
		return nil, nil, err
	}
	chk := &DomainCheck{At: state.Now()}
	txt, err := p.DNS.TXT(ctx, domains.ChallengeName(d.Hostname))
	if err != nil {
		chk.Ownership = "DNS lookup failed: " + err.Error()
	} else {
		chk.TXT = txt
		chk.Proven, chk.Ownership = txt.Proves(domains.TXTValue(inst, d.ClaimToken))
	}
	if t := p.routingTargets(); !t.Empty() {
		rc := domains.CheckRouting(ctx, p.DNS, d.Hostname, t)
		chk.Routing = &rc
	}
	if !chk.Proven {
		_ = p.Store.RecordDomainCheck(ctx, d.ID, chk)
		p.auditDomain(ctx, "domain.verify", d, audit.Denied, chk.Ownership)
		return d, chk, fmt.Errorf("%w: %s", ErrNotVerified, chk.Ownership)
	}
	if err := p.Store.MarkDomainVerified(ctx, d.ID, chk); err != nil {
		p.auditDomain(ctx, "domain.verify", d, audit.Denied, err.Error())
		return d, chk, err
	}
	p.auditDomain(ctx, "domain.verify", d, audit.Success, chk.Ownership)
	if err := p.reapplyRoutes(ctx); err != nil {
		p.Log.Warn("routes not applied after domain verification", "domain", d.Hostname, "err", err)
	}
	if p.Node.Ingress.Mode != "lan" {
		_, _ = p.Store.Enqueue(ctx, JobDomainCheck, "domaincheck:"+d.ID+":verify", map[string]string{"domain_id": d.ID}, tlsCheckAttempts)
	} else {
		_ = p.Store.SetDomainTLS(ctx, d.ID, "none")
	}
	p.Events.Publish(Event{Topic: "project:" + d.ProjectID, Type: "domain", Data: map[string]string{"id": d.ID, "status": "active"}})
	d, err = p.Store.GetDomain(ctx, d.ID)
	return d, chk, err
}

// DetachDomain removes a domain from routing and leaves a tombstone: a
// future claimant (even this project) must pass a fresh TXT challenge,
// whatever stale A/CNAME records still point here (step 7, SC-14).
func (p *Platform) DetachDomain(ctx context.Context, d *store.Domain) error {
	if err := p.Store.TombstoneDomain(ctx, d.ID); err != nil {
		return err
	}
	p.auditDomain(ctx, "domain.detach", d, audit.Success, "")
	return p.reapplyRoutes(ctx)
}

func (p *Platform) auditDomain(ctx context.Context, action string, d *store.Domain, result, reason string) {
	det := map[string]string{"domain": d.Hostname, "claim_id": d.ID}
	if d.EnvironmentID != "" {
		det["environment_id"] = d.EnvironmentID
	}
	if reason != "" {
		det["reason"] = truncate(reason, 500)
	}
	_, _ = p.Audit.Append(ctx, audit.Event{ActorType: audit.ActorService, ActorID: "platformd", Action: action, ResourceType: "domain",
		ResourceID: d.ID, ProjectID: d.ProjectID, Result: result, Details: det})
}

// checkDomainTLS confirms the edge serves a valid certificate for an
// active domain; retried with backoff while ACME issuance is in progress.
func (p *Platform) checkDomainTLS(ctx context.Context, job *store.Job, domainID string) error {
	d, err := p.Store.GetDomain(ctx, domainID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		return err
	}
	if d.Status != "active" || p.Node.Ingress.Mode == "lan" {
		return nil
	}
	probe := p.TLSProbe
	if probe == nil {
		probe = p.localTLSProbe
	}
	leaf, trusted, err := probe(ctx, d.Hostname)
	status, detail := "issuing", ""
	switch {
	case err != nil:
		detail = err.Error()
	case leaf.VerifyHostname(d.Hostname) != nil:
		detail = "edge certificate does not cover " + d.Hostname
	case time.Now().After(leaf.NotAfter):
		status, detail = "expired", "certificate expired "+leaf.NotAfter.Format(time.RFC3339)
	case !trusted && p.Node.Ingress.ACMECA == "":
		detail = "certificate issued by " + leaf.Issuer.CommonName + " is not publicly trusted yet"
	default:
		status, detail = "active", fmt.Sprintf("certificate from %s valid until %s", leaf.Issuer.CommonName, leaf.NotAfter.Format(time.RFC3339))
		if time.Until(leaf.NotAfter) < 14*24*time.Hour {
			status = "renewing"
		}
	}
	if status != "active" && status != "renewing" && job != nil && job.Attempts >= job.MaxAttempts {
		status = "error"
	}
	if d.TLSStatus != status {
		_ = p.Store.SetDomainTLS(ctx, d.ID, status)
		p.Events.Publish(Event{Topic: "project:" + d.ProjectID, Type: "domain", Data: map[string]string{"id": d.ID, "tls_status": status}})
	}
	if status == "issuing" || status == "expired" {
		return fmt.Errorf("%w: %s", ErrRetry, detail)
	}
	return nil
}

// localTLSProbe handshakes with the local edge using the domain as SNI.
func (p *Platform) localTLSProbe(ctx context.Context, host string) (*x509.Certificate, bool, error) {
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(p.Node.Ingress.HTTPSPort))
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := (&tls.Dialer{Config: &tls.Config{ServerName: host, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}}).DialContext(dctx, "tcp", addr) //nolint:gosec // chain verified explicitly below
	if err != nil {
		return nil, false, err
	}
	defer conn.Close()
	st := conn.(*tls.Conn).ConnectionState()
	if len(st.PeerCertificates) == 0 {
		return nil, false, errors.New("no certificate presented")
	}
	leaf := st.PeerCertificates[0]
	inter := x509.NewCertPool()
	for _, c := range st.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	_, verr := leaf.Verify(x509.VerifyOptions{DNSName: host, Intermediates: inter})
	return leaf, verr == nil, nil
}

// domainMaintenance expires stale claims and schedules periodic TLS
// re-checks (renewal monitoring) for attached domains.
func (p *Platform) domainMaintenance(ctx context.Context, now time.Time) {
	if n, err := p.Store.ExpireDomainClaims(ctx, now); err == nil && n > 0 {
		p.Log.Info("expired stale domain claims", "count", n)
	}
	if p.Node.Ingress.Mode == "lan" {
		return
	}
	ds, err := p.Store.ActiveDomains(ctx)
	if err != nil {
		return
	}
	bucket := now.UTC().Unix() / int64((6 * time.Hour).Seconds())
	for _, d := range ds {
		if d.Kind != "custom" {
			continue
		}
		_, _ = p.Store.Enqueue(ctx, JobDomainCheck, fmt.Sprintf("domaincheck:%s:%d", d.ID, bucket), map[string]string{"domain_id": d.ID}, tlsCheckAttempts)
	}
}
