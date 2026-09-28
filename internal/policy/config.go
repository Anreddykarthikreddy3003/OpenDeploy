// Package policy defines the opendeploy.yaml v2 project configuration
// (PRD §31), its defaults and its validation rules.
//
// The file is repository content and therefore untrusted input (PRD §3.1):
// parsing is strict (unknown fields rejected), sizes are bounded, and any
// request for elevated capability is recorded as a *request* that only an
// administrator policy can grant (SC-23). Nothing in this file can by itself
// raise a project's trust class.
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// MaxConfigBytes bounds the size of opendeploy.yaml read from a repository.
const MaxConfigBytes = 64 << 10

// FileName is the canonical config file name at the project root.
const FileName = "opendeploy.yaml"

type TrustClass string

const (
	TrustTrusted    TrustClass = "trusted"
	TrustUntrusted  TrustClass = "untrusted"
	TrustPrivileged TrustClass = "privileged"
)

type BuildStrategy string

const (
	StrategyAuto       BuildStrategy = "auto"
	StrategyBuildpacks BuildStrategy = "buildpacks"
	StrategyNixpacks   BuildStrategy = "nixpacks"
	StrategyDockerfile BuildStrategy = "dockerfile"
	StrategyStatic     BuildStrategy = "static"
	StrategyCompose    BuildStrategy = "compose"
)

type NetworkPolicy string

const (
	NetDependency NetworkPolicy = "dependency"
	NetRestricted NetworkPolicy = "restricted"
	NetOffline    NetworkPolicy = "offline"
)

type WorkloadType string

const (
	WorkloadWeb    WorkloadType = "web"
	WorkloadWorker WorkloadType = "worker"
	WorkloadCron   WorkloadType = "cron"
	WorkloadStatic WorkloadType = "static"
)

type Sandbox string

const (
	SandboxAuto   Sandbox = "auto"
	SandboxRunc   Sandbox = "runc"
	SandboxGVisor Sandbox = "gvisor"
	SandboxVM     Sandbox = "vm"
)

// Duration is a yaml-friendly time.Duration ("45s", "20m").
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q", s)
	}
	d.Duration = v
	return nil
}

func (d Duration) MarshalYAML() (any, error) { return d.String(), nil }

type Config struct {
	Version   int           `yaml:"version" json:"version"`
	Project   string        `yaml:"project" json:"project"`
	Source    SourceConfig  `yaml:"source" json:"source"`
	Build     BuildConfig   `yaml:"build" json:"build"`
	Runtime   RuntimeConfig `yaml:"runtime" json:"runtime"`
	Health    HealthConfig  `yaml:"health" json:"health"`
	Resources Resources     `yaml:"resources" json:"resources"`
	Egress    EgressConfig  `yaml:"egress" json:"egress"`
	Release   ReleaseConfig `yaml:"release" json:"release"`
	Previews  PreviewConfig `yaml:"previews" json:"previews"`
	Volumes   []Volume      `yaml:"volumes" json:"volumes"`
	Services  []Service     `yaml:"services,omitempty" json:"services,omitempty"`
	Cron      []CronJob     `yaml:"cron,omitempty" json:"cron,omitempty"`
}

type SourceConfig struct {
	ProductionBranch string     `yaml:"production_branch" json:"production_branch"`
	Trust            TrustClass `yaml:"trust" json:"trust"`
}

type BuildConfig struct {
	Strategy      BuildStrategy     `yaml:"strategy" json:"strategy"`
	Root          string            `yaml:"root" json:"root"`
	Dockerfile    string            `yaml:"dockerfile,omitempty" json:"dockerfile,omitempty"`
	Command       string            `yaml:"command,omitempty" json:"command,omitempty"`
	OutputDir     string            `yaml:"output_dir,omitempty" json:"output_dir,omitempty"`
	NetworkPolicy NetworkPolicy     `yaml:"network_policy" json:"network_policy"`
	Timeout       Duration          `yaml:"timeout" json:"timeout"`
	Args          map[string]string `yaml:"args,omitempty" json:"args,omitempty"`
	Secrets       []string          `yaml:"secrets,omitempty" json:"secrets,omitempty"`
}

type RuntimeConfig struct {
	Type         WorkloadType `yaml:"type" json:"type"`
	Port         int          `yaml:"port" json:"port"`
	Command      []string     `yaml:"command,omitempty" json:"command,omitempty"`
	Sandbox      Sandbox      `yaml:"sandbox" json:"sandbox"`
	ReadOnlyRoot *bool        `yaml:"read_only_root" json:"read_only_root"`
	Capabilities []string     `yaml:"capabilities" json:"capabilities"`
	Replicas     int          `yaml:"replicas,omitempty" json:"replicas,omitempty"`
	TmpfsPaths   []string     `yaml:"tmpfs,omitempty" json:"tmpfs,omitempty"`
}

type HealthConfig struct {
	Startup   *ProbeConfig `yaml:"startup" json:"startup"`
	Readiness *ProbeConfig `yaml:"readiness" json:"readiness"`
	Liveness  *ProbeConfig `yaml:"liveness" json:"liveness"`
	Smoke     []SmokeTest  `yaml:"smoke" json:"smoke"`
}

type ProbeConfig struct {
	Path     string   `yaml:"path" json:"path"`
	Grace    Duration `yaml:"grace" json:"grace"`
	Interval Duration `yaml:"interval" json:"interval"`
	Timeout  Duration `yaml:"timeout" json:"timeout"`
}

type SmokeTest struct {
	Name         string `yaml:"name" json:"name"`
	Request      string `yaml:"request" json:"request"`
	ExpectStatus int    `yaml:"expect_status" json:"expect_status"`
	ExpectBody   string `yaml:"expect_body,omitempty" json:"expect_body,omitempty"`
}

type Resources struct {
	Memory string  `yaml:"memory" json:"memory"`
	CPU    float64 `yaml:"cpu" json:"cpu"`
	PIDs   int     `yaml:"pids" json:"pids"`
	Disk   string  `yaml:"disk,omitempty" json:"disk,omitempty"`
}

type EgressConfig struct {
	Internet             *bool    `yaml:"internet" json:"internet"`
	AllowPrivateNetworks bool     `yaml:"allow_private_networks" json:"allow_private_networks"`
	AllowHosts           []string `yaml:"allow_hosts" json:"allow_hosts"`
}

type ReleaseConfig struct {
	ZeroDowntime    *bool `yaml:"zero_downtime" json:"zero_downtime"`
	KeepDeployments int   `yaml:"keep_deployments" json:"keep_deployments"`
	AutoPromote     *bool `yaml:"auto_promote" json:"auto_promote"`
}

type PreviewConfig struct {
	Enabled      bool   `yaml:"enabled" json:"enabled"`
	PublicForks  bool   `yaml:"public_forks" json:"public_forks"`
	SecretsScope string `yaml:"secrets_scope" json:"secrets_scope"`
	Database     string `yaml:"database" json:"database"`
	MaxActive    int    `yaml:"max_active" json:"max_active"`
}

type Volume struct {
	Name   string `yaml:"name" json:"name"`
	Mount  string `yaml:"mount" json:"mount"`
	Backup string `yaml:"backup" json:"backup"`
	Size   string `yaml:"size,omitempty" json:"size,omitempty"`
}

// Service is a supporting backing service (database/cache) template.
type Service struct {
	Name     string `yaml:"name" json:"name"`
	Template string `yaml:"template" json:"template"` // postgres | mysql | redis
	Version  string `yaml:"version,omitempty" json:"version,omitempty"`
	Volume   string `yaml:"volume,omitempty" json:"volume,omitempty"`
}

type CronJob struct {
	Name     string   `yaml:"name" json:"name"`
	Schedule string   `yaml:"schedule" json:"schedule"`
	Command  []string `yaml:"command" json:"command"`
}

// Parse decodes and validates opendeploy.yaml content. Unknown keys are
// rejected so typos cannot silently fall back to permissive defaults.
func Parse(data []byte) (*Config, error) {
	if len(data) > MaxConfigBytes {
		return nil, fmt.Errorf("%s exceeds %d bytes", FileName, MaxConfigBytes)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var c Config
	if err := dec.Decode(&c); err != nil {
		if errors.Is(err, io.EOF) {
			c = Config{}
		} else {
			return nil, fmt.Errorf("parse %s: %w", FileName, err)
		}
	}
	c.ApplyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func boolp(b bool) *bool { return &b }

// Default returns a configuration equivalent to an absent opendeploy.yaml.
func Default() *Config {
	c := &Config{}
	c.ApplyDefaults()
	return c
}

// ApplyDefaults fills zero values with secure defaults (PRD §31).
func (c *Config) ApplyDefaults() {
	if c.Version == 0 {
		c.Version = 2
	}
	if c.Source.ProductionBranch == "" {
		c.Source.ProductionBranch = "main"
	}
	if c.Source.Trust == "" {
		c.Source.Trust = TrustTrusted
	}
	if c.Build.Strategy == "" {
		c.Build.Strategy = StrategyAuto
	}
	if c.Build.Root == "" {
		c.Build.Root = "."
	}
	if c.Build.NetworkPolicy == "" {
		c.Build.NetworkPolicy = NetDependency
	}
	if c.Build.Timeout.Duration == 0 {
		c.Build.Timeout.Duration = 20 * time.Minute
	}
	if c.Runtime.Type == "" {
		c.Runtime.Type = WorkloadWeb
	}
	if c.Runtime.Port == 0 && c.Runtime.Type == WorkloadWeb {
		c.Runtime.Port = 8080
	}
	if c.Runtime.Sandbox == "" {
		c.Runtime.Sandbox = SandboxAuto
	}
	if c.Runtime.ReadOnlyRoot == nil {
		c.Runtime.ReadOnlyRoot = boolp(true)
	}
	if c.Runtime.Replicas == 0 {
		c.Runtime.Replicas = 1
	}
	if c.Resources.Memory == "" {
		c.Resources.Memory = "512Mi"
	}
	if c.Resources.CPU == 0 {
		c.Resources.CPU = 1.0
	}
	if c.Resources.PIDs == 0 {
		c.Resources.PIDs = 256
	}
	if c.Egress.Internet == nil {
		c.Egress.Internet = boolp(true)
	}
	if c.Release.ZeroDowntime == nil {
		c.Release.ZeroDowntime = boolp(true)
	}
	if c.Release.KeepDeployments == 0 {
		c.Release.KeepDeployments = 5
	}
	if c.Release.AutoPromote == nil {
		c.Release.AutoPromote = boolp(true)
	}
	if c.Previews.SecretsScope == "" {
		c.Previews.SecretsScope = "preview"
	}
	if c.Previews.Database == "" {
		c.Previews.Database = "ephemeral"
	}
	if c.Previews.MaxActive == 0 {
		c.Previews.MaxActive = 3
	}
	for i := range c.Health.Smoke {
		if c.Health.Smoke[i].ExpectStatus == 0 {
			c.Health.Smoke[i].ExpectStatus = 200
		}
	}
	for i := range c.Volumes {
		if c.Volumes[i].Backup == "" {
			c.Volumes[i].Backup = "daily"
		}
	}
}

var (
	nameRE      = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	memRE       = regexp.MustCompile(`^[0-9]+(Ki|Mi|Gi)$`)
	branchRE    = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,200}$`)
	smokeReqRE  = regexp.MustCompile(`^(GET|HEAD|POST|PUT|DELETE|PATCH|OPTIONS) /[^\s]*$`)
	hostRE      = regexp.MustCompile(`^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+(:[0-9]{1,5})?$`)
	cronFieldRE = regexp.MustCompile(`^(@(hourly|daily|weekly|monthly|yearly)|([0-9*/,-]+\s+){4}[0-9*/,-]+)$`)
)

// KnownCapabilities is the closed set of special capabilities that an
// administrator policy may grant (SC-23). Anything else is rejected.
var KnownCapabilities = map[string]bool{
	"gpu":          true,
	"fuse":         true,
	"usb":          true,
	"host-network": true,
	"kvm":          true,
}

// ServiceTemplates lists the built-in backing-service templates.
var ServiceTemplates = map[string]bool{"postgres": true, "mysql": true, "redis": true}

// ValidationError aggregates every problem found in a config.
type ValidationError struct{ Problems []string }

func (e *ValidationError) Error() string {
	return FileName + ": " + strings.Join(e.Problems, "; ")
}

// Validate checks structural and security constraints.
func (c *Config) Validate() error {
	var p []string
	add := func(f string, a ...any) { p = append(p, fmt.Sprintf(f, a...)) }

	if c.Version != 2 {
		add("unsupported version %d (expected 2)", c.Version)
	}
	if c.Project != "" && !nameRE.MatchString(c.Project) {
		add("project name %q must be a DNS label", c.Project)
	}
	if !branchRE.MatchString(c.Source.ProductionBranch) || strings.Contains(c.Source.ProductionBranch, "..") {
		add("invalid production_branch")
	}
	switch c.Source.Trust {
	case TrustTrusted, TrustUntrusted, TrustPrivileged:
	default:
		add("invalid source.trust %q", c.Source.Trust)
	}
	switch c.Build.Strategy {
	case StrategyAuto, StrategyBuildpacks, StrategyNixpacks, StrategyDockerfile, StrategyStatic, StrategyCompose:
	default:
		add("invalid build.strategy %q", c.Build.Strategy)
	}
	if err := checkRelPath(c.Build.Root); err != nil {
		add("build.root: %v", err)
	}
	if c.Build.Dockerfile != "" {
		if err := checkRelPath(c.Build.Dockerfile); err != nil {
			add("build.dockerfile: %v", err)
		}
	}
	if c.Build.OutputDir != "" {
		if err := checkRelPath(c.Build.OutputDir); err != nil {
			add("build.output_dir: %v", err)
		}
	}
	switch c.Build.NetworkPolicy {
	case NetDependency, NetRestricted, NetOffline:
	default:
		add("invalid build.network_policy %q", c.Build.NetworkPolicy)
	}
	if c.Build.Timeout.Duration < time.Minute || c.Build.Timeout.Duration > 2*time.Hour {
		add("build.timeout must be between 1m and 2h")
	}
	for _, s := range c.Build.Secrets {
		if !envNameRE.MatchString(s) {
			add("build.secrets entry %q is not a valid secret name", s)
		}
	}
	switch c.Runtime.Type {
	case WorkloadWeb:
		if c.Runtime.Port < 1 || c.Runtime.Port > 65535 {
			add("runtime.port must be 1-65535")
		}
	case WorkloadWorker, WorkloadCron, WorkloadStatic:
	default:
		add("invalid runtime.type %q", c.Runtime.Type)
	}
	switch c.Runtime.Sandbox {
	case SandboxAuto, SandboxRunc, SandboxGVisor, SandboxVM:
	default:
		add("invalid runtime.sandbox %q", c.Runtime.Sandbox)
	}
	if c.Runtime.Replicas < 1 || c.Runtime.Replicas > 16 {
		add("runtime.replicas must be 1-16")
	}
	for _, cap := range c.Runtime.Capabilities {
		if !KnownCapabilities[cap] {
			add("unknown capability %q", cap)
		}
	}
	for _, t := range c.Runtime.TmpfsPaths {
		if !strings.HasPrefix(t, "/") || strings.Contains(t, "..") {
			add("tmpfs path %q must be absolute", t)
		}
	}
	if !memRE.MatchString(c.Resources.Memory) {
		add("resources.memory %q must look like 512Mi", c.Resources.Memory)
	} else if b, _ := ParseMemory(c.Resources.Memory); b < 32<<20 {
		add("resources.memory must be at least 32Mi")
	}
	if c.Resources.CPU <= 0 || c.Resources.CPU > 64 {
		add("resources.cpu must be in (0, 64]")
	}
	if c.Resources.PIDs < 16 || c.Resources.PIDs > 32768 {
		add("resources.pids must be 16-32768")
	}
	for _, h := range c.Egress.AllowHosts {
		if !hostRE.MatchString(strings.ToLower(h)) {
			add("egress.allow_hosts entry %q is not a hostname", h)
		}
	}
	if c.Release.KeepDeployments < 1 || c.Release.KeepDeployments > 50 {
		add("release.keep_deployments must be 1-50")
	}
	if c.Previews.SecretsScope != "preview" && c.Previews.SecretsScope != "none" {
		// Production inheritance is never allowed from the repository file (SC-06/SC-09).
		add("previews.secrets_scope must be preview or none")
	}
	if c.Previews.Database != "ephemeral" && c.Previews.Database != "none" {
		add("previews.database must be ephemeral or none; production linkage requires administrator override")
	}
	if c.Previews.MaxActive < 0 || c.Previews.MaxActive > 50 {
		add("previews.max_active must be 0-50")
	}
	for _, s := range c.Health.Smoke {
		if !smokeReqRE.MatchString(s.Request) {
			add("smoke %q request must look like 'GET /path'", s.Name)
		}
		if s.ExpectStatus < 100 || s.ExpectStatus > 599 {
			add("smoke %q expect_status invalid", s.Name)
		}
	}
	for _, pr := range []*ProbeConfig{c.Health.Startup, c.Health.Readiness, c.Health.Liveness} {
		if pr != nil && !strings.HasPrefix(pr.Path, "/") {
			add("health probe path %q must start with /", pr.Path)
		}
	}
	seen := map[string]bool{}
	for _, v := range c.Volumes {
		if !nameRE.MatchString(v.Name) {
			add("volume name %q invalid", v.Name)
		}
		if seen[v.Name] {
			add("duplicate volume %q", v.Name)
		}
		seen[v.Name] = true
		if !strings.HasPrefix(v.Mount, "/") || strings.Contains(v.Mount, "..") || forbiddenMount(v.Mount) {
			add("volume %q mount %q not allowed", v.Name, v.Mount)
		}
		switch v.Backup {
		case "none", "hourly", "daily", "weekly":
		default:
			add("volume %q backup must be none|hourly|daily|weekly", v.Name)
		}
		if v.Size != "" && !memRE.MatchString(v.Size) {
			add("volume %q size invalid", v.Name)
		}
	}
	for _, s := range c.Services {
		if !nameRE.MatchString(s.Name) {
			add("service name %q invalid", s.Name)
		}
		if !ServiceTemplates[s.Template] {
			add("service %q template %q unsupported", s.Name, s.Template)
		}
		if s.Volume != "" && !seen[s.Volume] {
			add("service %q references unknown volume %q", s.Name, s.Volume)
		}
	}
	for _, j := range c.Cron {
		if !nameRE.MatchString(j.Name) {
			add("cron name %q invalid", j.Name)
		}
		if !cronFieldRE.MatchString(strings.TrimSpace(j.Schedule)) {
			add("cron %q schedule invalid", j.Name)
		}
		if len(j.Command) == 0 {
			add("cron %q requires a command", j.Name)
		}
	}
	if len(p) > 0 {
		return &ValidationError{Problems: p}
	}
	return nil
}

var envNameRE = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)

// ValidEnvName reports whether s is an acceptable secret/env name.
func ValidEnvName(s string) bool { return envNameRE.MatchString(s) }

func checkRelPath(s string) error {
	if s == "" {
		return errors.New("empty path")
	}
	if strings.HasPrefix(s, "/") || strings.HasPrefix(s, "\\") {
		return errors.New("must be relative to the repository")
	}
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == '/' || r == '\\' }) {
		if part == ".." {
			return errors.New("must not escape the repository")
		}
	}
	return nil
}

// forbiddenMount rejects mount targets that would shadow sensitive paths.
func forbiddenMount(m string) bool {
	m = strings.TrimRight(m, "/")
	if m == "" {
		return true
	}
	for _, p := range []string{"/etc", "/bin", "/sbin", "/usr", "/lib", "/lib64", "/boot"} {
		if m == p {
			return true
		}
	}
	for _, p := range []string{"/proc", "/sys", "/dev", "/run", "/var/run"} {
		if m == p || strings.HasPrefix(m, p+"/") {
			return true
		}
	}
	return false
}

// ParseMemory converts "512Mi" style quantities to bytes.
func ParseMemory(s string) (int64, error) {
	if !memRE.MatchString(s) {
		return 0, fmt.Errorf("invalid quantity %q", s)
	}
	var n int64
	unit := s[len(s)-2:]
	if _, err := fmt.Sscanf(s[:len(s)-2], "%d", &n); err != nil {
		return 0, err
	}
	switch unit {
	case "Ki":
		return n << 10, nil
	case "Mi":
		return n << 20, nil
	default:
		return n << 30, nil
	}
}
