// Types mirror the Go API (internal/api, internal/store).

export type Role = "owner" | "admin" | "developer" | "viewer";

export interface User {
  id: string;
  email: string;
  name: string;
  role: Role;
  totp_enabled: boolean;
  webauthn_count: number;
  disabled: boolean;
  created_at: string;
}

export interface SessionInfo {
  user: User;
  mfa_required: boolean;
  mfa_enrollment_required: boolean;
  csrf_token: string;
  mfa_methods?: string[];
}

export interface BuildOverrides {
  strategy?: string;
  build_command?: string;
  start_command?: string;
  output_dir?: string;
  port?: number;
  env?: Record<string, string>;
}

export interface Project {
  id: string;
  name: string;
  git_connection_id?: string;
  repo_id: number;
  repo_full_name: string;
  clone_url: string;
  root_dir: string;
  production_branch: string;
  trust_class: "trusted" | "untrusted" | "privileged";
  prefer_gvisor: boolean;
  allow_public_forks: boolean;
  previews_enabled: boolean;
  auto_deploy: boolean;
  granted_capabilities: string[];
  config_override?: string;
  build_overrides: BuildOverrides;
  created_at: string;
  updated_at: string;
}

export type DeploymentStatus =
  | "RECEIVED"
  | "VALIDATING"
  | "FETCHING"
  | "DETECTING"
  | "BUILDING"
  | "ARTIFACT_READY"
  | "STARTING_CANDIDATE"
  | "HEALTH_CHECKING"
  | "READY"
  | "PROMOTION_INTENT"
  | "ROUTER_SWITCHED"
  | "COMMITTING_POINTER"
  | "DRAINING_OLD"
  | "SUCCEEDED"
  | "FAILED"
  | "SUPERSEDED"
  | "CANCELLED";

export const TERMINAL_STATUSES: DeploymentStatus[] = ["SUCCEEDED", "FAILED", "SUPERSEDED", "CANCELLED"];

export interface Deployment {
  id: string;
  project_id: string;
  environment_id: string;
  generation: number;
  trigger: string;
  commit_sha: string;
  commit_message: string;
  commit_author: string;
  branch: string;
  rollback_of?: string;
  artifact_id?: string;
  status: DeploymentStatus;
  trust_class: string;
  runtime_class: string;
  build_strategy: string;
  decision_reasons: string[] | null;
  error?: string;
  created_by: string;
  created_at: string;
  updated_at: string;
  started_at?: string;
  finished_at?: string;
}

export interface Environment {
  id: string;
  project_id: string;
  name: string;
  kind: "production" | "staging" | "preview" | string;
  branch: string;
  pr_number?: number;
  pr_from_fork?: boolean;
  desired_generation: number;
  observed_generation: number;
  current_deployment_id: string;
  generated_hostname: string;
  status: string;
  created_at: string;
}

export interface EnvSummary extends Environment {
  url?: string;
  domains: string[];
  current_deployment?: Deployment;
  latest_deployment?: Deployment;
}

export interface ProjectView extends Project {
  role: Role;
  url?: string;
  production?: EnvSummary;
  source_kind: "github" | "git" | "upload";
}

export interface ProjectDetail {
  project: ProjectView;
  environments: EnvSummary[];
}

export interface DeploymentEvent {
  id: number;
  at: string;
  from: string;
  to: string;
  message: string;
}

export interface Workload {
  id: string;
  service_name: string;
  replica: number;
  state: string;
  endpoint: string;
  runtime_class: string;
}

export interface Artifact {
  id: string;
  kind: string;
  digest: string;
  image_ref: string;
  size_bytes: number;
  created_at: string;
}

export interface DeploymentDetail {
  deployment: Deployment;
  project: Project;
  environment: Environment;
  events: DeploymentEvent[] | null;
  workloads: Workload[] | null;
  artifact?: Artifact | null;
  url: string;
  is_current: boolean;
}

export interface LogLine {
  id: number;
  stream: string;
  at: string;
  line: string;
}

export interface RuntimeLogLine {
  workload: string;
  replica: number;
  time: string;
  stream: string;
  text: string;
}

export interface SecretMeta {
  id: string;
  scope: string;
  project_id?: string;
  environment_id?: string;
  name: string;
  version: number;
  sensitive: boolean;
  build_visible: boolean;
  created_at: string;
  created_by: string;
  preview?: string;
}

export interface DomainInstructions {
  txt_name: string;
  txt_value: string;
  expires_at: string;
  routing: { ips?: string[]; hosts?: string[] };
  ingress_mode: string;
  note?: string;
}

export interface Domain {
  id: string;
  hostname: string;
  project_id: string;
  environment_id: string;
  kind: string;
  status: "pending" | "verified" | "active" | "detached" | "tombstoned" | "expired";
  claim_expires_at?: string;
  verified_at?: string;
  ingress_mode: string;
  tls_status: string;
  last_check: any;
  created_at: string;
  instructions?: DomainInstructions;
}

export interface Plan {
  commit: { sha: string; ref?: string; message?: string; author?: string };
  plan: {
    strategy: string;
    stack: string;
    framework?: string;
    package_manager?: string;
    dockerfile?: string;
    generated: boolean;
    port: number;
    static_output: boolean;
    static_dir?: string;
    build_command?: string;
    start_command?: string;
    runtime_version?: string;
    reasons: string[];
    warnings?: string[];
  };
  dockerfile?: string;
  error?: string;
}

export interface GitConnection {
  id: string;
  provider: string;
  app_id: number;
  installation_id: number;
  account_login: string;
  account_type: string;
  status: string;
  created_at: string;
}

export interface GitStatus {
  configured: boolean;
  connections: GitConnection[];
  public_url: string;
  install_url?: string;
  error?: string;
}

export interface Repo {
  connection_id: string;
  account: string;
  id: number;
  full_name: string;
  private: boolean;
  default_branch: string;
  html_url: string;
  imported: boolean;
}

export interface Member {
  user_id: string;
  email: string;
  name: string;
  role: Role;
}

export interface AuditEvent {
  seq: number;
  time: string;
  service: string;
  actor_type: string;
  actor_id: string;
  session_id?: string;
  mfa: boolean;
  source_ip?: string;
  action: string;
  resource_type?: string;
  resource_id?: string;
  project_id?: string;
  result: "success" | "denied" | "failure";
  details?: Record<string, string>;
  hash: string;
}

export interface Session {
  id: string;
  current: boolean;
  created_at: string;
  last_seen_at: string;
  source_ip: string;
  user_agent: string;
  mfa: boolean;
}

export interface APIToken {
  id: string;
  name: string;
  role_cap: string;
  created_at: string;
  expires_at: string;
  last_used_at?: string;
}

export interface Volume {
  id: string;
  project_id: string;
  environment_id: string;
  name: string;
  mount_target: string;
  size_bytes: number;
  deletion_protection: boolean;
  backup_policy: string;
  status: string;
  created_at: string;
}

export interface Job {
  id: string;
  kind: string;
  idempotency_key: string;
  state: string;
  attempts: number;
  max_attempts: number;
  run_after: string;
  last_error: string;
  created_at: string;
}
