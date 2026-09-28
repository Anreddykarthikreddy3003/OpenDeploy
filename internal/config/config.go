// Package config loads the node configuration (/etc/opendeploy/node.yaml)
// shared by all OpenDeploy services.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/identity"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/ipc"
)

// DefaultPath is the default node configuration location.
const DefaultPath = "/etc/opendeploy/node.yaml"

type Node struct {
	DataDir string `yaml:"data_dir"`
	RunDir  string `yaml:"run_dir"`
	// Profile is tiny | standard | performance (PRD §18.2).
	Profile string `yaml:"profile"`
	// DevMode runs all services as one user with declared IPC identities.
	// It is refused unless OPENDEPLOY_INSECURE_DEV=1 is also set.
	DevMode bool `yaml:"dev_mode"`

	API      APIConfig      `yaml:"api"`
	GitHub   GitHubConfig   `yaml:"github"`
	Ingress  IngressConfig  `yaml:"ingress"`
	Runtime  RuntimeConfig  `yaml:"runtime"`
	Build    BuildConfig    `yaml:"build"`
	Egress   EgressConfig   `yaml:"egress"`
	Audit    AuditConfig    `yaml:"audit"`
	Backup   BackupConfig   `yaml:"backup"`
	Update   UpdateConfig   `yaml:"update"`
	Secrets  SecretsConfig  `yaml:"secrets"`
	Identity IdentityConfig `yaml:"identity"`
	Artifact ArtifactConfig `yaml:"artifact"`
}

type ArtifactConfig struct {
	RegistryListen string `yaml:"registry_listen"`
	MaxImageBytes  int64  `yaml:"max_image_bytes"`
}

type APIConfig struct {
	Listen       string            `yaml:"listen"`
	PublicURL    string            `yaml:"public_url"`
	RemoteAdmin  RemoteAdminConfig `yaml:"remote_admin"`
	TrustedProxy []string          `yaml:"trusted_proxies"`
}

type RemoteAdminConfig struct {
	Enabled      bool     `yaml:"enabled"`
	Acknowledged bool     `yaml:"acknowledged_risk"`
	AllowedCIDRs []string `yaml:"allowed_cidrs"`
	TLSCert      string   `yaml:"tls_cert"`
	TLSKey       string   `yaml:"tls_key"`
}

type GitHubConfig struct {
	AppID             int64  `yaml:"app_id"`
	AppSlug           string `yaml:"app_slug"`
	PrivateKeyFile    string `yaml:"private_key_file"`
	WebhookSecretFile string `yaml:"webhook_secret_file"`
	APIURL            string `yaml:"api_url"`
	ClientID          string `yaml:"client_id"`
	ClientSecretFile  string `yaml:"client_secret_file"`
}

type IngressConfig struct {
	Mode        string      `yaml:"mode"` // lan | direct | relay
	BaseDomain  string      `yaml:"base_domain"`
	ACMEEmail   string      `yaml:"acme_email"`
	ACMECA      string      `yaml:"acme_ca"`
	PublicIPv4  string      `yaml:"public_ipv4"`
	PublicIPv6  string      `yaml:"public_ipv6"`
	HTTPPort    int         `yaml:"http_port"`
	HTTPSPort   int         `yaml:"https_port"`
	CaddyAdmin  string      `yaml:"caddy_admin_socket"`
	Relay       RelayConfig `yaml:"relay"`
	DNSResolver string      `yaml:"dns_resolver"`
	Limits      EdgeLimits  `yaml:"limits"`
}

type EdgeLimits struct {
	MaxBodyBytes      int64 `yaml:"max_body_bytes"`
	RequestsPerSecond int   `yaml:"requests_per_second"`
	MaxConnsPerHost   int   `yaml:"max_conns_per_host"`
}

type RelayConfig struct {
	ServerAddr   string `yaml:"server_addr"`
	ServerName   string `yaml:"server_name"`
	CAFile       string `yaml:"ca_file"`
	CertFile     string `yaml:"cert_file"`
	KeyFile      string `yaml:"key_file"`
	EnrollToken  string `yaml:"enroll_token_file"`
	TenantID     string `yaml:"tenant_id"`
	InstanceID   string `yaml:"instance_id"`
	PublicSuffix string `yaml:"public_suffix"`
}

type RuntimeConfig struct {
	Backend          string `yaml:"backend"` // containerd | docker
	ContainerdSocket string `yaml:"containerd_socket"`
	ContainerdNS     string `yaml:"containerd_namespace"`
	DockerHost       string `yaml:"docker_host"`
	RuncHandler      string `yaml:"runc_handler"`
	RunscHandler     string `yaml:"runsc_handler"`
	VMHandler        string `yaml:"vm_handler"`
	VolumesDir       string `yaml:"volumes_dir"`
}

type BuildConfig struct {
	// Executor is buildkit (rootless buildkitd via buildctl, default) or
	// docker (the Docker Engine's BuildKit; dev/CI adapter).
	Executor          string `yaml:"executor"`
	BuildKitAddr      string `yaml:"buildkit_addr"`
	UntrustedBuildKit string `yaml:"untrusted_buildkit_addr"`
	// UntrustedRuntime enables disposable sandboxed BuildKit containers on
	// Docker-engine nodes (e.g. "runsc"). Empty = untrusted builds fail closed
	// unless untrusted_buildkit_addr points at an operator-run sandbox.
	UntrustedRuntime    string `yaml:"untrusted_runtime"`
	UntrustedImage      string `yaml:"untrusted_image"`
	UntrustedNetwork    string `yaml:"untrusted_network"`
	WorkDir             string `yaml:"work_dir"`
	CacheDir            string `yaml:"cache_dir"`
	MaxConcurrent       int    `yaml:"max_concurrent"`
	PackPath            string `yaml:"pack_path"`
	NixpacksPath        string `yaml:"nixpacks_path"`
	Registry            string `yaml:"registry"`
	DefaultBuilderImage string `yaml:"default_builder_image"`
}

type EgressConfig struct {
	ProxyListen  string   `yaml:"proxy_listen"`
	BuildBridges []string `yaml:"build_bridges"`
	BuildUsers   []string `yaml:"build_users"` // rootless BuildKit users (output filtering)
	DNS          []string `yaml:"dns"`
	NftBin       string   `yaml:"nft_bin"`
	AllowedHosts []string `yaml:"allowed_hosts"` // registries etc. for restricted builds
	Enforce      bool     `yaml:"enforce"`
}

type AuditConfig struct {
	Forward []AuditForward `yaml:"forward"`
}

type AuditForward struct {
	Name      string `yaml:"name"`
	URL       string `yaml:"url"`
	TokenFile string `yaml:"token_file"`
}

type BackupConfig struct {
	Enabled    bool   `yaml:"enabled"`
	Schedule   string `yaml:"schedule"`
	Endpoint   string `yaml:"endpoint"`
	Bucket     string `yaml:"bucket"`
	Region     string `yaml:"region"`
	Prefix     string `yaml:"prefix"`
	AccessKey  string `yaml:"access_key_file"`
	SecretKey  string `yaml:"secret_key_file"`
	MasterKey  string `yaml:"master_key_file"`
	UseSSL     *bool  `yaml:"use_ssl"`
	ObjectLock bool   `yaml:"object_lock"`
	RetainDays int    `yaml:"retain_days"`
	LocalDir   string `yaml:"local_dir"`
}

type UpdateConfig struct {
	RepositoryURL string `yaml:"repository_url"`
	Channel       string `yaml:"channel"`
	TrustedRoot   string `yaml:"trusted_root"`
	SlotsDir      string `yaml:"slots_dir"`
	AutoStage     bool   `yaml:"auto_stage"`
}

type SecretsConfig struct {
	KEKFile string `yaml:"kek_file"`
}

// IdentityConfig overrides the Unix user for each service identity.
type IdentityConfig struct {
	Users map[string]string `yaml:"users"`
}

// Load reads and validates the node configuration. A missing file yields
// defaults.
func Load(path string) (*Node, error) {
	n := &Node{}
	b, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if len(b) > 0 {
		dec := yaml.NewDecoder(bytes.NewReader(b))
		dec.KnownFields(true)
		if err := dec.Decode(n); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	n.ApplyDefaults()
	return n, n.Validate()
}

func (n *Node) ApplyDefaults() {
	def := func(p *string, v string) {
		if *p == "" {
			*p = v
		}
	}
	defi := func(p *int, v int) {
		if *p == 0 {
			*p = v
		}
	}
	def(&n.DataDir, "/var/lib/opendeploy")
	def(&n.RunDir, "/run/opendeploy")
	def(&n.Profile, "standard")
	def(&n.API.Listen, "127.0.0.1:7070")
	def(&n.GitHub.APIURL, "https://api.github.com")
	def(&n.Ingress.Mode, "lan")
	def(&n.Ingress.CaddyAdmin, filepath.Join(n.RunDir, "caddy-admin.sock"))
	def(&n.Ingress.DNSResolver, "1.1.1.1:53")
	defi(&n.Ingress.HTTPPort, 80)
	defi(&n.Ingress.HTTPSPort, 443)
	if n.Ingress.Limits.MaxBodyBytes == 0 {
		n.Ingress.Limits.MaxBodyBytes = 100 << 20
	}
	defi(&n.Ingress.Limits.RequestsPerSecond, 200)
	defi(&n.Ingress.Limits.MaxConnsPerHost, 1024)
	def(&n.Runtime.Backend, "containerd")
	def(&n.Runtime.ContainerdSocket, "/run/containerd/containerd.sock")
	def(&n.Runtime.ContainerdNS, "opendeploy")
	def(&n.Runtime.DockerHost, "unix:///var/run/docker.sock")
	def(&n.Runtime.RuncHandler, "io.containerd.runc.v2")
	def(&n.Runtime.RunscHandler, "io.containerd.runsc.v1")
	def(&n.Runtime.VMHandler, "io.containerd.kata.v2")
	def(&n.Runtime.VolumesDir, filepath.Join(n.DataDir, "volumes"))
	if n.Build.Executor == "" {
		n.Build.Executor = "buildkit"
		if n.Runtime.Backend == "docker" {
			n.Build.Executor = "docker"
		}
	}
	def(&n.Build.BuildKitAddr, "unix://"+filepath.Join(n.RunDir, "buildkit", "buildkitd.sock"))
	def(&n.Build.WorkDir, filepath.Join(n.DataDir, "build"))
	def(&n.Build.CacheDir, filepath.Join(n.DataDir, "build-cache"))
	def(&n.Build.PackPath, "pack")
	def(&n.Build.NixpacksPath, "nixpacks")
	def(&n.Build.UntrustedImage, "moby/buildkit:v0.24.0-rootless")
	def(&n.Build.DefaultBuilderImage, "paketobuildpacks/builder-jammy-base")
	def(&n.Egress.ProxyListen, "0.0.0.0:3128")
	if len(n.Egress.BuildBridges) == 0 && n.Runtime.Backend == "docker" {
		n.Egress.BuildBridges = []string{"docker0"}
	}
	def(&n.Backup.Schedule, "@daily")
	def(&n.Backup.Prefix, "opendeploy/")
	defi(&n.Backup.RetainDays, 30)
	def(&n.Backup.LocalDir, filepath.Join(n.DataDir, "backups"))
	def(&n.Update.Channel, "stable")
	def(&n.Update.SlotsDir, "/opt/opendeploy/slots")
	def(&n.Artifact.RegistryListen, "127.0.0.1:5010")
	if n.Artifact.MaxImageBytes == 0 {
		n.Artifact.MaxImageBytes = 10 << 30
	}
	def(&n.Secrets.KEKFile, filepath.Join(n.DataDir, "secretd", "kek"))
	if n.Build.MaxConcurrent == 0 {
		switch n.Profile {
		case "tiny":
			n.Build.MaxConcurrent = 1
		case "performance":
			n.Build.MaxConcurrent = 4
		default:
			n.Build.MaxConcurrent = 2
		}
	}
}

// Validate enforces startup safety rules. In particular an unsafe wildcard
// bind of the admin API without an acknowledged remote-management
// configuration fails startup (PRD §15.1, SC-11).
func (n *Node) Validate() error {
	var p []string
	switch n.Profile {
	case "tiny", "standard", "performance":
	default:
		p = append(p, "profile must be tiny|standard|performance")
	}
	switch n.Ingress.Mode {
	case "lan", "direct", "relay":
	default:
		p = append(p, "ingress.mode must be lan|direct|relay")
	}
	switch n.Build.Executor {
	case "buildkit", "docker":
	default:
		p = append(p, "build.executor must be buildkit|docker")
	}
	switch n.Runtime.Backend {
	case "containerd", "docker":
	default:
		p = append(p, "runtime.backend must be containerd|docker")
	}
	host, _, err := net.SplitHostPort(n.API.Listen)
	if err != nil {
		p = append(p, "api.listen must be host:port")
	} else if err := checkAdminBind(host, n.API.RemoteAdmin); err != nil {
		p = append(p, err.Error())
	}
	if n.API.RemoteAdmin.Enabled {
		if n.API.RemoteAdmin.TLSCert == "" || n.API.RemoteAdmin.TLSKey == "" {
			p = append(p, "remote_admin requires tls_cert and tls_key")
		}
		if len(n.API.RemoteAdmin.AllowedCIDRs) == 0 {
			p = append(p, "remote_admin requires allowed_cidrs")
		}
		for _, c := range n.API.RemoteAdmin.AllowedCIDRs {
			if _, err := netip.ParsePrefix(c); err != nil {
				p = append(p, "invalid allowed_cidrs entry "+c)
			}
		}
	}
	if n.Ingress.Mode == "relay" {
		r := n.Ingress.Relay
		if r.ServerAddr == "" {
			p = append(p, "ingress.relay.server_addr required in relay mode")
		} else if _, _, err := net.SplitHostPort(r.ServerAddr); err != nil {
			p = append(p, "ingress.relay.server_addr must be host:port")
		}
		if !dnsLabel(r.InstanceID) || !dnsLabel(r.TenantID) {
			p = append(p, "ingress.relay.instance_id and tenant_id must be DNS labels (a-z, 0-9, '-') in relay mode")
		}
		if r.PublicSuffix == "" {
			p = append(p, "ingress.relay.public_suffix required in relay mode")
		}
	}
	if n.DevMode && os.Getenv("OPENDEPLOY_INSECURE_DEV") != "1" {
		p = append(p, "dev_mode requires OPENDEPLOY_INSECURE_DEV=1 (never use in production)")
	}
	if len(p) > 0 {
		return errors.New("node config: " + strings.Join(p, "; "))
	}
	return nil
}

func checkAdminBind(host string, ra RemoteAdminConfig) error {
	if host == "" || host == "0.0.0.0" || host == "::" {
		if !ra.Enabled || !ra.Acknowledged {
			return errors.New("api.listen is a wildcard address; set remote_admin.enabled and remote_admin.acknowledged_risk (with TLS, MFA and allowed_cidrs) or bind to loopback")
		}
		return nil
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		if host == "localhost" {
			return nil
		}
		return fmt.Errorf("api.listen host %q must be an IP address", host)
	}
	if ip.IsLoopback() {
		return nil
	}
	if !ra.Enabled || !ra.Acknowledged {
		return fmt.Errorf("api.listen %s is not loopback; remote administration must be explicitly enabled and acknowledged", host)
	}
	return nil
}

// Socket returns the IPC socket path for a service identity.
func (n *Node) Socket(id string) string { return filepath.Join(n.RunDir, id+".sock") }

// HandoffDir is the build-output handoff directory (builderd writes,
// artifactd reads and re-validates).
func (n *Node) HandoffDir() string { return filepath.Join(n.DataDir, "handoff") }

// ServiceDir returns the private state directory for a service identity.
func (n *Node) ServiceDir(id string) string { return filepath.Join(n.DataDir, id) }

// IdentityMap resolves each service identity's Unix user to its UID.
func (n *Node) IdentityMap() (*ipc.IdentityMap, error) {
	m := map[uint32]string{}
	if !n.DevMode {
		for _, id := range identity.All {
			name := identity.UnixUser(id)
			if u, ok := n.Identity.Users[id]; ok {
				name = u
			}
			usr, err := user.Lookup(name)
			if err != nil {
				continue // service not installed on this node
			}
			uid, _ := strconv.ParseUint(usr.Uid, 10, 32)
			if prev, dup := m[uint32(uid)]; dup {
				return nil, fmt.Errorf("identities %s and %s share uid %d; each service needs its own user", prev, id, uid)
			}
			m[uint32(uid)] = id
		}
	}
	im := ipc.NewIdentityMap(m)
	im.DevIdentityHeader = n.DevMode
	return im, nil
}

// IPCClient returns a client for the given service, declaring self in dev mode.
func (n *Node) IPCClient(target, self string) *ipc.Client {
	c := ipc.NewClient(n.Socket(target))
	if n.DevMode {
		c = c.WithDevIdentity(self)
	}
	return c
}

// ReadSecretFile reads a small credential file and trims whitespace.
func ReadSecretFile(p string) ([]byte, error) {
	if p == "" {
		return nil, errors.New("no file configured")
	}
	fi, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s must not be group/world accessible (mode %v)", p, fi.Mode().Perm())
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	return bytes.TrimSpace(b), nil
}

func dnsLabel(s string) bool {
	if len(s) < 2 || len(s) > 40 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}
