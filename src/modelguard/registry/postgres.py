"""PostgreSQL-backed ``Registry``.

Requires the optional dependency: ``pip install "modelguard[postgres]"``.

SECURITY MODEL (read before deploying)
--------------------------------------
* **Connection strings are secrets.** The DSN is held in memory only,
  never logged, never included in an exception message, and the CLI
  reads it from an environment variable, not argv (argv is visible to
  other local users via ``ps``).
* **Transport.** A DSN with a non-local host must set
  ``sslmode=verify-full`` or ``verify-ca``; ``require`` and weaker
  encrypt the channel but do not authenticate the server, so a
  man-in-the-middle can read and alter registry answers -- including
  "not revoked". Loopback and unix-socket hosts are exempt. Override
  with ``allow_insecure_transport=True`` only for tests.
* **Fail closed.** Any backend problem raises ``RegistryBackendError``.
  ``ModelGuard.verify`` lets it propagate and ``admit()`` denies; an
  outage is never interpreted as "not revoked".
* **Least privilege.** Use two roles: an owner/migration role that runs
  ``migrate()``, and an application role granted only ``SELECT, INSERT``
  on ``registry_records`` and ``revocation_events``, ``USAGE`` on their
  sequences, and ``SELECT`` on ``modelguard_schema_migrations`` (see
  ``docs/limitations.md``).
* **Immutability is enforced by the database** (see ``migrations.py``),
  but a superuser or table owner can defeat it.
* No connection pooling: one short-lived connection per operation.
  Correct and simple; a pooled variant is future work.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import psycopg
from psycopg import errors as pg_errors
from psycopg.conninfo import conninfo_to_dict
from psycopg.types.json import Jsonb
from pydantic import ValidationError

from modelguard.audit.chain import ChainIntegrityError
from modelguard.registry.errors import (
    DuplicateRegistrationError,
    RegistryBackendError,
    RegistryConfigurationError,
)
from modelguard.registry.identifiers import validate_identifier
from modelguard.registry.migrations import BOOTSTRAP_SQL, LATEST_VERSION, MIGRATIONS
from modelguard.registry.models import RegistryRecord, RevocationRecord

_GENESIS_HASH = "0" * 64
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_VERIFYING_SSLMODES = frozenset({"verify-ca", "verify-full"})
# Two distinct advisory-lock keys: one serializes migrators, one
# serializes appends to the revocation hash chain.
_MIGRATION_LOCK = 0x4D475F4D  # "MG_M"
_REVOCATION_LOCK = 0x4D475F52  # "MG_R"


def _check_dsn(dsn: str, allow_insecure_transport: bool) -> None:
    try:
        parts = conninfo_to_dict(dsn)
    except psycopg.ProgrammingError as exc:
        raise RegistryConfigurationError("The PostgreSQL DSN is malformed.") from exc

    host = parts.get("host")
    if not host:
        raise RegistryConfigurationError(
            "The PostgreSQL DSN must name a host explicitly (or a unix-socket directory); "
            "relying on PGHOST would let ambient environment redirect the registry."
        )
    hosts = [h.strip() for h in str(host).split(",")]
    remote = [h for h in hosts if h not in _LOCAL_HOSTS and not h.startswith("/")]
    if remote and not allow_insecure_transport and parts.get("sslmode") not in _VERIFYING_SSLMODES:
        raise RegistryConfigurationError(
            "Refusing a non-local PostgreSQL host without sslmode=verify-full (or verify-ca). "
            "Weaker modes do not authenticate the server, so an attacker on the network path "
            "could forge revocation answers. Set sslmode=verify-full in the DSN."
        )


def _category(exc: psycopg.Error) -> str:
    state = exc.sqlstate or ""
    if state.startswith("28"):
        return "authentication failed"
    if state == "42501":
        return "permission denied"
    if state == "57014":
        return "statement timeout"
    if state == "MG01" or state == "MG001":
        return "append-only violation"
    if not state and isinstance(exc, psycopg.OperationalError):
        # libpq reports connect-time failures without an SQLSTATE, so the
        # message is the only signal. It is used ONLY to pick a category
        # label; the text itself is never copied into our error.
        text = str(exc).lower()
        if "authentication failed" in text or "no pg_hba.conf entry" in text:
            return "authentication failed"
        return "could not connect or connection lost"
    return "database error"


def _canonical(record: dict[str, Any]) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _event_hash(prev_hash: str, record: dict[str, Any]) -> str:
    return hashlib.sha256(prev_hash.encode("ascii") + _canonical(record)).hexdigest()


class PostgresRegistry:
    """``Registry`` implementation backed by PostgreSQL."""

    def __init__(
        self,
        dsn: str,
        *,
        allow_insecure_transport: bool = False,
        connect_timeout_s: int = 5,
        statement_timeout_ms: int = 10_000,
    ) -> None:
        _check_dsn(dsn, allow_insecure_transport)
        self._dsn = dsn
        self._connect_timeout_s = connect_timeout_s
        self._statement_timeout_ms = statement_timeout_ms
        self._schema_verified = False

    def __repr__(self) -> str:  # never expose the DSN via repr/logging
        return "PostgresRegistry(dsn=<redacted>)"

    # -- connection ----------------------------------------------------

    @contextmanager
    def _connect(self, action: str, *, check_schema: bool = True) -> Iterator[psycopg.Connection[Any]]:
        try:
            with psycopg.connect(
                self._dsn,
                connect_timeout=self._connect_timeout_s,
                options=f"-c statement_timeout={self._statement_timeout_ms}",
                application_name="modelguard",
            ) as conn:
                if check_schema and not self._schema_verified:
                    self._verify_schema(conn)
                    self._schema_verified = True
                yield conn
        except (RegistryBackendError, DuplicateRegistrationError):
            raise
        except psycopg.Error as exc:
            raise RegistryBackendError(
                f"PostgreSQL registry {action} failed: {_category(exc)} "
                f"({type(exc).__name__}, sqlstate={exc.sqlstate or 'none'})."
            ) from None

    def _verify_schema(self, conn: psycopg.Connection[Any]) -> None:
        try:
            rows = conn.execute(
                "SELECT version, checksum FROM modelguard_schema_migrations ORDER BY version"
            ).fetchall()
        except pg_errors.UndefinedTable:
            conn.rollback()
            raise RegistryBackendError(
                "The registry schema is not initialized. Run the migration as the owner role: "
                "PostgresRegistry(...).migrate()."
            ) from None
        applied = {int(v): str(c) for v, c in rows}
        if not applied or max(applied) < LATEST_VERSION:
            raise RegistryBackendError(
                f"The registry schema is at version {max(applied, default=0)} but this ModelGuard "
                f"needs {LATEST_VERSION}. Run migrate() as the owner role."
            )
        if max(applied) > LATEST_VERSION:
            raise RegistryBackendError(
                f"The registry schema (v{max(applied)}) is newer than this ModelGuard "
                f"(v{LATEST_VERSION}). Upgrade ModelGuard; refusing to operate on a schema it "
                "does not understand."
            )
        _check_checksums(applied)

    # -- migrations ------------------------------------------------------

    def migrate(self) -> list[int]:
        """Apply pending migrations; return the versions applied.

        Run as a role with DDL privileges. Refuses if an already-applied
        migration's checksum differs from the shipped one, or if the
        database is newer than this code.
        """
        applied_now: list[int] = []
        with self._connect("migration", check_schema=False) as conn:
            conn.execute("SELECT pg_advisory_xact_lock(%s)", (_MIGRATION_LOCK,))
            conn.execute(BOOTSTRAP_SQL)
            rows = conn.execute("SELECT version, checksum FROM modelguard_schema_migrations").fetchall()
            applied = {int(v): str(c) for v, c in rows}
            if applied and max(applied) > LATEST_VERSION:
                raise RegistryBackendError(
                    f"The registry schema (v{max(applied)}) is newer than this ModelGuard "
                    f"(v{LATEST_VERSION}); refusing to migrate."
                )
            _check_checksums(applied)
            for migration in MIGRATIONS:
                if migration.version in applied:
                    continue
                conn.execute(migration.sql)
                conn.execute(
                    "INSERT INTO modelguard_schema_migrations (version, name, checksum) "
                    "VALUES (%s, %s, %s)",
                    (migration.version, migration.name, migration.checksum),
                )
                applied_now.append(migration.version)
        return applied_now

    # -- registration ----------------------------------------------------

    def register(self, record: RegistryRecord) -> RegistryRecord:
        validate_identifier(record.model_id, field="model_id")
        validate_identifier(record.version, field="version")
        with self._connect("registration") as conn:
            try:
                conn.execute(
                    "INSERT INTO registry_records "
                    "(model_id, version, artifact_digest, record, registered_by) "
                    "VALUES (%s, %s, %s, %s, %s)",
                    (
                        record.model_id,
                        record.version,
                        record.artifact_digest,
                        Jsonb(record.model_dump(mode="json")),
                        record.registered_by,
                    ),
                )
            except pg_errors.UniqueViolation:
                raise DuplicateRegistrationError(record.model_id, record.version) from None
        return record

    def get(self, model_id: str, version: str) -> RegistryRecord | None:
        validate_identifier(model_id, field="model_id")
        validate_identifier(version, field="version")
        with self._connect("lookup") as conn:
            row = conn.execute(
                "SELECT model_id, version, artifact_digest, record FROM registry_records "
                "WHERE model_id = %s AND version = %s",
                (model_id, version),
            ).fetchone()
        return None if row is None else _row_to_record(row)

    def get_by_digest(self, artifact_digest: str) -> RegistryRecord | None:
        # Earliest registration wins, so re-registering identical bytes
        # under another name can never repoint an existing identity.
        with self._connect("lookup") as conn:
            row = conn.execute(
                "SELECT model_id, version, artifact_digest, record FROM registry_records "
                "WHERE artifact_digest = %s ORDER BY id LIMIT 1",
                (artifact_digest,),
            ).fetchone()
        return None if row is None else _row_to_record(row)

    def list_versions(self, model_id: str) -> list[str]:
        validate_identifier(model_id, field="model_id")
        with self._connect("lookup") as conn:
            rows = conn.execute(
                'SELECT version FROM registry_records WHERE model_id = %s ORDER BY version COLLATE "C"',
                (model_id,),
            ).fetchall()
        return [str(r[0]) for r in rows]

    # -- revocation --------------------------------------------------------

    def revoke(self, record: RevocationRecord) -> RevocationRecord:
        self._append_event("revoke", record.model_id, record.version, record.revoked_by, record.reason, record.revoked_at)
        return record

    def unrevoke(self, model_id: str, version: str, actor: str, reason: str) -> None:
        from datetime import UTC, datetime

        self._append_event("unrevoke", model_id, version, actor, reason, datetime.now(UTC).isoformat())

    def _append_event(
        self, action: str, model_id: str, version: str, actor: str, reason: str, revoked_at: str
    ) -> None:
        validate_identifier(model_id, field="model_id")
        validate_identifier(version, field="version")
        body = {
            "action": action,
            "model_id": model_id,
            "version": version,
            "actor": actor,
            "reason": reason,
            "revoked_at": revoked_at,
        }
        with self._connect("revocation") as conn:
            # Serialize chain appends so concurrent writers cannot fork it.
            conn.execute("SELECT pg_advisory_xact_lock(%s)", (_REVOCATION_LOCK,))
            last = conn.execute(
                "SELECT event_hash FROM revocation_events ORDER BY id DESC LIMIT 1"
            ).fetchone()
            prev = str(last[0]) if last else _GENESIS_HASH
            conn.execute(
                "INSERT INTO revocation_events "
                "(model_id, version, action, actor, reason, revoked_at, prev_hash, event_hash) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                (model_id, version, action, actor, reason, revoked_at, prev, _event_hash(prev, body)),
            )

    def is_revoked(self, model_id: str, version: str) -> RevocationRecord | None:
        validate_identifier(model_id, field="model_id")
        validate_identifier(version, field="version")
        with self._connect("revocation lookup") as conn:
            row = conn.execute(
                "SELECT action, actor, reason, revoked_at FROM revocation_events "
                "WHERE model_id = %s AND version = %s ORDER BY id DESC LIMIT 1",
                (model_id, version),
            ).fetchone()
        if row is None or row[0] != "revoke":
            return None
        return RevocationRecord(
            model_id=model_id,
            version=version,
            revoked_by=str(row[1]),
            reason=str(row[2]),
            revoked_at=str(row[3]),
        )

    def verify_revocation_chain(self) -> None:
        """Recompute the revocation hash chain; raise ``ChainIntegrityError``
        on any edit, reordering, or mid-chain deletion.

        Like the local logs, this cannot detect deletion of the *most
        recent* events (nothing later references them).
        """
        with self._connect("chain verification") as conn:
            rows = conn.execute(
                "SELECT action, model_id, version, actor, reason, revoked_at, prev_hash, event_hash "
                "FROM revocation_events ORDER BY id"
            ).fetchall()
        prev = _GENESIS_HASH
        for index, (action, model_id, version, actor, reason, revoked_at, prev_hash, event_hash) in enumerate(rows):
            if prev_hash != prev:
                raise ChainIntegrityError(index, "prev_hash does not match the preceding event")
            body = {
                "action": action,
                "model_id": model_id,
                "version": version,
                "actor": actor,
                "reason": reason,
                "revoked_at": revoked_at,
            }
            if _event_hash(prev, body) != event_hash:
                raise ChainIntegrityError(index, "event contents do not match their hash")
            prev = event_hash


def _check_checksums(applied: dict[int, str]) -> None:
    shipped = {m.version: m.checksum for m in MIGRATIONS}
    for version, checksum in applied.items():
        if version in shipped and shipped[version] != checksum:
            raise RegistryBackendError(
                f"Migration {version} was applied with different SQL than this ModelGuard ships "
                "(checksum mismatch). Refusing to operate on a schema that may not be what the "
                "code expects."
            )


def _row_to_record(row: tuple[Any, ...]) -> RegistryRecord:
    model_id, version, digest, payload = row
    try:
        record = RegistryRecord.model_validate(payload)
    except ValidationError:
        raise RegistryBackendError(
            "A stored registry record failed validation; the registry data may be corrupt."
        ) from None
    if (record.model_id, record.version, record.artifact_digest) != (model_id, version, digest):
        raise RegistryBackendError(
            "A stored registry record disagrees with its indexed columns; refusing to trust it."
        )
    return record
