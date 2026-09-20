"""Versioned, checksummed schema migrations for ``PostgresRegistry``.

Migrations are Python string constants (not loose ``.sql`` files) so
they ship inside the wheel and their checksums are fixed by the
release. The applied checksum is stored; if a shipped migration's SQL
ever differs from what was applied, the registry refuses to run rather
than assume the schema is what the code expects.

Rules: never edit a released migration -- add a new one.

Immutability is enforced in the database, not just in application
code: ``registry_records``, ``revocation_events`` and the migrations
table reject UPDATE, DELETE and TRUNCATE through triggers. That stops
an application bug or a stolen *application-role* credential from
rewriting history. It does NOT stop a database superuser or table
owner, who can drop the triggers -- see ``docs/limitations.md``.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

_MIGRATION_1 = """
CREATE TABLE registry_records (
    id              bigserial PRIMARY KEY,
    model_id        text NOT NULL CHECK (char_length(model_id) BETWEEN 1 AND 200),
    version         text NOT NULL CHECK (char_length(version) BETWEEN 1 AND 200),
    artifact_digest text NOT NULL CHECK (artifact_digest ~ '^sha256:[0-9a-f]{64}$'),
    record          jsonb NOT NULL,
    registered_by   text NOT NULL,
    registered_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (model_id, version)
);
CREATE INDEX registry_records_digest_idx ON registry_records (artifact_digest, id);

CREATE TABLE revocation_events (
    id          bigserial PRIMARY KEY,
    model_id    text NOT NULL CHECK (char_length(model_id) BETWEEN 1 AND 200),
    version     text NOT NULL CHECK (char_length(version) BETWEEN 1 AND 200),
    action      text NOT NULL CHECK (action IN ('revoke', 'unrevoke')),
    actor       text NOT NULL,
    reason      text NOT NULL,
    revoked_at  text NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT now(),
    prev_hash   text NOT NULL CHECK (prev_hash ~ '^[0-9a-f]{64}$'),
    event_hash  text NOT NULL UNIQUE CHECK (event_hash ~ '^[0-9a-f]{64}$')
);
CREATE INDEX revocation_events_model_idx ON revocation_events (model_id, version, id DESC);

CREATE FUNCTION modelguard_forbid_mutation() RETURNS trigger
LANGUAGE plpgsql AS $fn$
BEGIN
    RAISE EXCEPTION 'modelguard: % on % is not permitted (append-only)', TG_OP, TG_TABLE_NAME
        USING ERRCODE = 'MG001';
END;
$fn$;

CREATE TRIGGER registry_records_append_only
    BEFORE UPDATE OR DELETE ON registry_records
    FOR EACH ROW EXECUTE FUNCTION modelguard_forbid_mutation();
CREATE TRIGGER registry_records_no_truncate
    BEFORE TRUNCATE ON registry_records
    FOR EACH STATEMENT EXECUTE FUNCTION modelguard_forbid_mutation();

CREATE TRIGGER revocation_events_append_only
    BEFORE UPDATE OR DELETE ON revocation_events
    FOR EACH ROW EXECUTE FUNCTION modelguard_forbid_mutation();
CREATE TRIGGER revocation_events_no_truncate
    BEFORE TRUNCATE ON revocation_events
    FOR EACH STATEMENT EXECUTE FUNCTION modelguard_forbid_mutation();

CREATE TRIGGER schema_migrations_append_only
    BEFORE UPDATE OR DELETE ON modelguard_schema_migrations
    FOR EACH ROW EXECUTE FUNCTION modelguard_forbid_mutation();
CREATE TRIGGER schema_migrations_no_truncate
    BEFORE TRUNCATE ON modelguard_schema_migrations
    FOR EACH STATEMENT EXECUTE FUNCTION modelguard_forbid_mutation();
"""

BOOTSTRAP_SQL = """
CREATE TABLE IF NOT EXISTS modelguard_schema_migrations (
    version    integer PRIMARY KEY,
    name       text NOT NULL,
    checksum   text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
)
"""


@dataclass(frozen=True, slots=True)
class Migration:
    version: int
    name: str
    sql: str

    @property
    def checksum(self) -> str:
        return hashlib.sha256(self.sql.encode("utf-8")).hexdigest()


MIGRATIONS: tuple[Migration, ...] = (Migration(1, "initial_registry", _MIGRATION_1),)
LATEST_VERSION = MIGRATIONS[-1].version
