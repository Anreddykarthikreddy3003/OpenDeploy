-- auditd-owned security audit chain (SC-20). Append-only by trigger;
-- tampering at the file level is detected by hash-chain verification.
CREATE TABLE audit_events (
    seq           INTEGER PRIMARY KEY,
    ts            TEXT NOT NULL,
    service       TEXT NOT NULL,
    actor_type    TEXT NOT NULL,
    actor_id      TEXT NOT NULL,
    session_id    TEXT NOT NULL,
    mfa           INTEGER NOT NULL,
    source_ip     TEXT NOT NULL,
    action        TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id   TEXT NOT NULL,
    project_id    TEXT NOT NULL,
    result        TEXT NOT NULL,
    details       TEXT NOT NULL,
    prev_hash     TEXT NOT NULL,
    hash          TEXT NOT NULL UNIQUE
);
CREATE INDEX audit_project ON audit_events(project_id, seq);
CREATE INDEX audit_action ON audit_events(action, seq);

CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;

CREATE TABLE audit_checkpoints (
    seq       INTEGER PRIMARY KEY,
    hash      TEXT NOT NULL,
    ts        TEXT NOT NULL,
    key_id    TEXT NOT NULL,
    signature TEXT NOT NULL
);

CREATE TABLE audit_forwarding (
    sink         TEXT PRIMARY KEY,
    last_seq     INTEGER NOT NULL,
    updated_at   TEXT NOT NULL,
    last_error   TEXT NOT NULL DEFAULT ''
);
