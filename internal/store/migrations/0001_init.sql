-- OpenDeploy platform metadata schema v1 (PRD §20).
-- Secrets live in secretd's own database; security audit lives in auditd's.

CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE users (
    id              TEXT PRIMARY KEY,
    email           TEXT NOT NULL UNIQUE COLLATE NOCASE,
    name            TEXT NOT NULL DEFAULT '',
    password_hash   TEXT NOT NULL,
    role            TEXT NOT NULL CHECK (role IN ('owner','admin','developer','viewer')),
    totp_secret_enc BLOB,
    totp_enabled    INTEGER NOT NULL DEFAULT 0,
    totp_last_step  INTEGER NOT NULL DEFAULT 0,
    failed_logins   INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT NOT NULL DEFAULT '',
    disabled        INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE TABLE webauthn_credentials (
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name          TEXT NOT NULL DEFAULT '',
    credential_id BLOB NOT NULL UNIQUE,
    data          BLOB NOT NULL,
    created_at    TEXT NOT NULL,
    last_used_at  TEXT NOT NULL DEFAULT ''
);

CREATE TABLE recovery_codes (
    user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used_at   TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (user_id, code_hash)
);

CREATE TABLE sessions (
    id            TEXT PRIMARY KEY,           -- sha256(token), never the token
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token    TEXT NOT NULL,
    mfa_verified  INTEGER NOT NULL DEFAULT 0,
    mfa_method    TEXT NOT NULL DEFAULT '',
    reauth_at     TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL,
    last_seen_at  TEXT NOT NULL,
    expires_at    TEXT NOT NULL,
    idle_expires_at TEXT NOT NULL,
    source_ip     TEXT NOT NULL DEFAULT '',
    user_agent    TEXT NOT NULL DEFAULT '',
    revoked_at    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX sessions_user ON sessions(user_id);

CREATE TABLE api_tokens (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    role_cap     TEXT NOT NULL CHECK (role_cap IN ('admin','developer','viewer')),
    created_at   TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    last_used_at TEXT NOT NULL DEFAULT '',
    revoked_at   TEXT NOT NULL DEFAULT ''
);

CREATE TABLE git_connections (
    id                 TEXT PRIMARY KEY,
    provider           TEXT NOT NULL CHECK (provider IN ('github')),
    app_id             INTEGER NOT NULL,
    installation_id    INTEGER NOT NULL,
    account_login      TEXT NOT NULL DEFAULT '',
    account_type       TEXT NOT NULL DEFAULT '',
    status             TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','revoked')),
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL,
    UNIQUE (provider, installation_id)
);

CREATE TABLE projects (
    id                  TEXT PRIMARY KEY,
    name                TEXT NOT NULL UNIQUE,
    git_connection_id   TEXT REFERENCES git_connections(id),
    repo_id             INTEGER NOT NULL DEFAULT 0,
    repo_full_name      TEXT NOT NULL DEFAULT '',
    clone_url           TEXT NOT NULL DEFAULT '',
    root_dir            TEXT NOT NULL DEFAULT '.',
    production_branch   TEXT NOT NULL DEFAULT 'main',
    trust_class         TEXT NOT NULL DEFAULT 'trusted' CHECK (trust_class IN ('trusted','untrusted','privileged')),
    prefer_gvisor       INTEGER NOT NULL DEFAULT 0,
    allow_public_forks  INTEGER NOT NULL DEFAULT 0,
    previews_enabled    INTEGER NOT NULL DEFAULT 0,
    auto_deploy         INTEGER NOT NULL DEFAULT 1,
    granted_capabilities TEXT NOT NULL DEFAULT '[]',
    config_override     TEXT NOT NULL DEFAULT '',
    build_overrides     TEXT NOT NULL DEFAULT '{}',
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    deleted_at          TEXT NOT NULL DEFAULT ''
);
CREATE INDEX projects_repo ON projects(repo_id);

CREATE TABLE project_members (
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role       TEXT NOT NULL CHECK (role IN ('admin','developer','viewer')),
    PRIMARY KEY (project_id, user_id)
);

CREATE TABLE environments (
    id                    TEXT PRIMARY KEY,
    project_id            TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name                  TEXT NOT NULL,
    kind                  TEXT NOT NULL CHECK (kind IN ('production','staging','preview')),
    branch                TEXT NOT NULL DEFAULT '',
    pr_number             INTEGER NOT NULL DEFAULT 0,
    pr_from_fork          INTEGER NOT NULL DEFAULT 0,
    desired_generation    INTEGER NOT NULL DEFAULT 0,
    observed_generation   INTEGER NOT NULL DEFAULT 0,
    desired_deployment_id TEXT NOT NULL DEFAULT '',
    current_deployment_id TEXT NOT NULL DEFAULT '',
    generated_hostname    TEXT NOT NULL DEFAULT '',
    status                TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','stopped','deleting','deleted')),
    created_at            TEXT NOT NULL,
    updated_at            TEXT NOT NULL,
    UNIQUE (project_id, name),
    CHECK (observed_generation <= desired_generation)
);

CREATE TABLE artifacts (
    id          TEXT PRIMARY KEY,
    project_id  TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL CHECK (kind IN ('oci','static')),
    digest      TEXT NOT NULL,
    image_ref   TEXT NOT NULL DEFAULT '',
    size_bytes  INTEGER NOT NULL DEFAULT 0,
    config      TEXT NOT NULL DEFAULT '{}',
    sbom_digest TEXT NOT NULL DEFAULT '',
    provenance  TEXT NOT NULL DEFAULT '{}',
    created_at  TEXT NOT NULL,
    UNIQUE (project_id, digest)
);

CREATE TABLE deployments (
    id               TEXT PRIMARY KEY,
    project_id       TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    environment_id   TEXT NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    generation       INTEGER NOT NULL,
    trigger          TEXT NOT NULL CHECK (trigger IN ('push','pull_request','manual','rollback','redeploy')),
    commit_sha       TEXT NOT NULL DEFAULT '',
    commit_message   TEXT NOT NULL DEFAULT '',
    commit_author    TEXT NOT NULL DEFAULT '',
    branch           TEXT NOT NULL DEFAULT '',
    delivery_id      TEXT NOT NULL DEFAULT '',
    rollback_of      TEXT NOT NULL DEFAULT '',
    status           TEXT NOT NULL,
    trust_class      TEXT NOT NULL DEFAULT '',
    runtime_class    TEXT NOT NULL DEFAULT '',
    build_strategy   TEXT NOT NULL DEFAULT '',
    build_inputs     TEXT NOT NULL DEFAULT '{}',
    config_snapshot  TEXT NOT NULL DEFAULT '{}',
    artifact_id      TEXT REFERENCES artifacts(id),
    decision_reasons TEXT NOT NULL DEFAULT '[]',
    error            TEXT NOT NULL DEFAULT '',
    created_by       TEXT NOT NULL DEFAULT '',
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    started_at       TEXT NOT NULL DEFAULT '',
    finished_at      TEXT NOT NULL DEFAULT '',
    UNIQUE (environment_id, generation)
);
CREATE INDEX deployments_env ON deployments(environment_id, created_at);
CREATE INDEX deployments_status ON deployments(status);

CREATE TABLE deployment_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    deployment_id TEXT NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
    at            TEXT NOT NULL,
    from_status   TEXT NOT NULL,
    to_status     TEXT NOT NULL,
    message       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX deployment_events_dep ON deployment_events(deployment_id, id);

CREATE TABLE deployment_logs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    deployment_id TEXT NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
    stream        TEXT NOT NULL CHECK (stream IN ('build','deploy','runtime','system')),
    at            TEXT NOT NULL,
    line          TEXT NOT NULL
);
CREATE INDEX deployment_logs_dep ON deployment_logs(deployment_id, id);

CREATE TABLE workloads (
    id             TEXT PRIMARY KEY,
    deployment_id  TEXT NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
    environment_id TEXT NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    service_name   TEXT NOT NULL DEFAULT 'web',
    replica        INTEGER NOT NULL DEFAULT 0,
    runtime_id     TEXT NOT NULL DEFAULT '',
    runtime_class  TEXT NOT NULL DEFAULT '',
    endpoint       TEXT NOT NULL DEFAULT '',
    state          TEXT NOT NULL CHECK (state IN ('creating','running','healthy','unhealthy','draining','stopped','failed')),
    started_at     TEXT NOT NULL DEFAULT '',
    stopped_at     TEXT NOT NULL DEFAULT '',
    updated_at     TEXT NOT NULL
);
CREATE INDEX workloads_dep ON workloads(deployment_id);

CREATE TABLE domains (
    id               TEXT PRIMARY KEY,
    hostname         TEXT NOT NULL COLLATE NOCASE,
    project_id       TEXT REFERENCES projects(id) ON DELETE SET NULL,
    environment_id   TEXT REFERENCES environments(id) ON DELETE SET NULL,
    kind             TEXT NOT NULL CHECK (kind IN ('custom','generated')),
    status           TEXT NOT NULL CHECK (status IN ('pending','verified','active','detached','tombstoned','expired')),
    claim_token      TEXT NOT NULL DEFAULT '',
    claim_expires_at TEXT NOT NULL DEFAULT '',
    verified_at      TEXT NOT NULL DEFAULT '',
    ingress_mode     TEXT NOT NULL DEFAULT 'direct' CHECK (ingress_mode IN ('lan','direct','relay')),
    tls_status       TEXT NOT NULL DEFAULT 'none',
    last_check       TEXT NOT NULL DEFAULT '{}',
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    tombstoned_at    TEXT NOT NULL DEFAULT ''
);
-- Globally unique ACTIVE ownership (SC-14).
CREATE UNIQUE INDEX domains_active_unique ON domains(hostname) WHERE status IN ('verified','active');
CREATE INDEX domains_host ON domains(hostname);

CREATE TABLE services (
    id             TEXT PRIMARY KEY,
    project_id     TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    environment_id TEXT NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    name           TEXT NOT NULL,
    template       TEXT NOT NULL,
    version        TEXT NOT NULL DEFAULT '',
    runtime_class  TEXT NOT NULL DEFAULT 'runc',
    desired_state  TEXT NOT NULL DEFAULT 'running' CHECK (desired_state IN ('running','stopped','deleted')),
    runtime_id     TEXT NOT NULL DEFAULT '',
    endpoint       TEXT NOT NULL DEFAULT '',
    volume_id      TEXT NOT NULL DEFAULT '',
    credentials_secret TEXT NOT NULL DEFAULT '',
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL,
    UNIQUE (environment_id, name)
);

CREATE TABLE volumes (
    id                  TEXT PRIMARY KEY,
    project_id          TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    environment_id      TEXT NOT NULL REFERENCES environments(id) ON DELETE RESTRICT,
    name                TEXT NOT NULL,
    mount_target        TEXT NOT NULL,
    size_bytes          INTEGER NOT NULL DEFAULT 0,
    deletion_protection INTEGER NOT NULL DEFAULT 1,
    backup_policy       TEXT NOT NULL DEFAULT 'daily',
    status              TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','tombstoned')),
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    tombstoned_at       TEXT NOT NULL DEFAULT '',
    UNIQUE (environment_id, name)
);

CREATE TABLE promotion_intents (
    id              TEXT PRIMARY KEY,
    environment_id  TEXT NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    from_deployment TEXT NOT NULL DEFAULT '',
    to_deployment   TEXT NOT NULL,
    generation      INTEGER NOT NULL,
    router_digest   TEXT NOT NULL DEFAULT '',
    state           TEXT NOT NULL CHECK (state IN ('pending','router_applied','committed','complete','aborted')),
    error           TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);
-- At most one in-flight promotion per environment.
CREATE UNIQUE INDEX promotion_inflight ON promotion_intents(environment_id) WHERE state IN ('pending','router_applied','committed');

CREATE TABLE jobs (
    id              TEXT PRIMARY KEY,
    kind            TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    payload         TEXT NOT NULL DEFAULT '{}',
    state           TEXT NOT NULL CHECK (state IN ('queued','running','succeeded','failed','dead','cancelled')),
    attempts        INTEGER NOT NULL DEFAULT 0,
    max_attempts    INTEGER NOT NULL DEFAULT 5,
    run_after       TEXT NOT NULL,
    locked_by       TEXT NOT NULL DEFAULT '',
    locked_until    TEXT NOT NULL DEFAULT '',
    last_error      TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);
CREATE INDEX jobs_ready ON jobs(state, run_after);

CREATE TABLE webhook_deliveries (
    delivery_id     TEXT PRIMARY KEY,
    event           TEXT NOT NULL,
    action          TEXT NOT NULL DEFAULT '',
    installation_id INTEGER NOT NULL DEFAULT 0,
    repository_id   INTEGER NOT NULL DEFAULT 0,
    ref             TEXT NOT NULL DEFAULT '',
    sha             TEXT NOT NULL DEFAULT '',
    body_sha256     TEXT NOT NULL,
    received_at     TEXT NOT NULL,
    outcome         TEXT NOT NULL DEFAULT ''
);

CREATE TABLE circuit_breakers (
    key          TEXT PRIMARY KEY,
    state        TEXT NOT NULL CHECK (state IN ('closed','open','half_open')),
    failures     INTEGER NOT NULL DEFAULT 0,
    last_error   TEXT NOT NULL DEFAULT '',
    opened_at    TEXT NOT NULL DEFAULT '',
    next_attempt TEXT NOT NULL DEFAULT '',
    updated_at   TEXT NOT NULL
);

CREATE TABLE nodes (
    id           TEXT PRIMARY KEY,
    hostname     TEXT NOT NULL,
    capabilities TEXT NOT NULL DEFAULT '{}',
    profile      TEXT NOT NULL DEFAULT 'standard',
    version      TEXT NOT NULL DEFAULT '',
    update_slot  TEXT NOT NULL DEFAULT 'a',
    last_seen    TEXT NOT NULL
);

CREATE TABLE backups (
    id              TEXT PRIMARY KEY,
    kind            TEXT NOT NULL CHECK (kind IN ('full','metadata','volume','database')),
    status          TEXT NOT NULL CHECK (status IN ('running','succeeded','failed','verified')),
    target          TEXT NOT NULL DEFAULT '',
    manifest_digest TEXT NOT NULL DEFAULT '',
    object_key      TEXT NOT NULL DEFAULT '',
    size_bytes      INTEGER NOT NULL DEFAULT 0,
    error           TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL,
    completed_at    TEXT NOT NULL DEFAULT '',
    restore_tested_at TEXT NOT NULL DEFAULT ''
);
