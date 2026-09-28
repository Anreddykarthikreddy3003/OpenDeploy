-- secretd-owned secret store (SC-06). Values are envelope-encrypted:
-- value --AES-256-GCM(DEK, aad=identity)--> ciphertext
-- DEK   --AES-256-GCM(KEK, aad=kek_id|identity)--> wrapped_dek
CREATE TABLE secrets (
    id               TEXT PRIMARY KEY,
    scope            TEXT NOT NULL CHECK (scope IN ('instance','project','preview','environment')),
    project_id       TEXT NOT NULL DEFAULT '',
    environment_id   TEXT NOT NULL DEFAULT '',
    name             TEXT NOT NULL,
    version          INTEGER NOT NULL,
    sensitive        INTEGER NOT NULL DEFAULT 1,
    build_visible    INTEGER NOT NULL DEFAULT 0,
    ciphertext       BLOB NOT NULL,
    nonce            BLOB NOT NULL,
    wrapped_dek      BLOB NOT NULL,
    dek_nonce        BLOB NOT NULL,
    kek_id           TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    created_by       TEXT NOT NULL DEFAULT '',
    superseded_at    TEXT NOT NULL DEFAULT '',
    deleted_at       TEXT NOT NULL DEFAULT '',
    UNIQUE (scope, project_id, environment_id, name, version)
);
CREATE INDEX secrets_lookup ON secrets(project_id, environment_id, scope, name);
CREATE UNIQUE INDEX secrets_current ON secrets(scope, project_id, environment_id, name) WHERE superseded_at = '' AND deleted_at = '';

CREATE TABLE keks (
    id          TEXT PRIMARY KEY,
    created_at  TEXT NOT NULL,
    retired_at  TEXT NOT NULL DEFAULT ''
);
