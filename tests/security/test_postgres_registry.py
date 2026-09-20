"""Security and integrity tests for PostgresRegistry, against a real database."""

from __future__ import annotations

import threading
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

psycopg = pytest.importorskip("psycopg")
from psycopg.conninfo import make_conninfo

from modelguard.admission import admit
from modelguard.audit.chain import ChainIntegrityError
from modelguard.policy.models import Decision
from modelguard.registry import RegistryBackendError, RevocationRecord
from modelguard.registry.migrations import LATEST_VERSION
from modelguard.registry.postgres import PostgresRegistry
from modelguard.sdk import ModelGuard
from tests.conftest import SignedModel
from tests.unit.test_registry_contract import make_record


@pytest.fixture
def registry(pg_dsn: str) -> PostgresRegistry:
    return PostgresRegistry(pg_dsn)


def _owner(dsn: str) -> psycopg.Connection:  # type: ignore[type-arg]
    return psycopg.connect(dsn, autocommit=True)


def _revoke(registry: PostgresRegistry, n: int = 1) -> None:
    for i in range(n):
        registry.revoke(RevocationRecord(model_id="m", version=str(i), revoked_by="sec", reason=f"r{i}"))


# -- append-only enforcement -------------------------------------------------


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE registry_records SET registered_by = 'attacker'",
        "DELETE FROM registry_records",
        "TRUNCATE registry_records",
        "UPDATE revocation_events SET action = 'unrevoke'",
        "DELETE FROM revocation_events",
        "TRUNCATE revocation_events",
        "UPDATE modelguard_schema_migrations SET checksum = 'x'",
        "DELETE FROM modelguard_schema_migrations",
    ],
)
def test_history_cannot_be_rewritten_even_by_the_table_owner(
    registry: PostgresRegistry, pg_dsn: str, tmp_path: Path, statement: str
) -> None:
    registry.register(make_record(tmp_path))
    _revoke(registry)
    with _owner(pg_dsn) as conn, pytest.raises(psycopg.Error) as exc:
        conn.execute(statement)  # type: ignore[call-overload]
    assert exc.value.sqlstate == "MG001"


def test_unrevoking_is_a_new_event_not_an_edit(registry: PostgresRegistry, pg_dsn: str, tmp_path: Path) -> None:
    registry.register(make_record(tmp_path, "m", "0"))
    _revoke(registry)
    registry.unrevoke("m", "0", actor="sec", reason="ok")
    with _owner(pg_dsn) as conn:
        rows = conn.execute("SELECT action FROM revocation_events ORDER BY id").fetchall()
    assert [r[0] for r in rows] == ["revoke", "unrevoke"]


# -- least privilege ---------------------------------------------------------


@pytest.fixture
def app_dsn(pg_dsn: str) -> Iterator[str]:
    """DSN for a role that can only SELECT/INSERT -- the intended runtime role."""
    role = f"mg_app_{uuid.uuid4().hex[:8]}"
    with _owner(pg_dsn) as conn:
        try:
            conn.execute(f"CREATE ROLE {role} LOGIN PASSWORD 'app_pw'")  # type: ignore[call-overload]
        except psycopg.errors.InsufficientPrivilege:
            pytest.skip("test database role lacks CREATEROLE")
        conn.execute(  # type: ignore[call-overload]
            f"GRANT SELECT, INSERT ON registry_records, revocation_events TO {role}"
        )
        conn.execute(f"GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO {role}")  # type: ignore[call-overload]
        conn.execute(f"GRANT SELECT ON modelguard_schema_migrations TO {role}")  # type: ignore[call-overload]
    try:
        yield make_conninfo(pg_dsn, user=role, password="app_pw")
    finally:
        with _owner(pg_dsn) as conn:
            conn.execute(  # type: ignore[call-overload]
                f"REVOKE ALL ON registry_records, revocation_events, "
                f"modelguard_schema_migrations FROM {role}"
            )
            conn.execute(f"REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM {role}")  # type: ignore[call-overload]
            conn.execute(f"DROP ROLE {role}")  # type: ignore[call-overload]


def test_runtime_role_with_minimal_grants_can_do_everything_the_registry_needs(
    app_dsn: str, tmp_path: Path
) -> None:
    app = PostgresRegistry(app_dsn)
    record = make_record(tmp_path)
    app.register(record)
    assert app.get("demo", "1.0.0") == record
    app.revoke(RevocationRecord(model_id="demo", version="1.0.0", revoked_by="s", reason="r"))
    assert app.is_revoked("demo", "1.0.0") is not None
    app.verify_revocation_chain()


def test_runtime_role_cannot_modify_history_or_schema(app_dsn: str, tmp_path: Path) -> None:
    PostgresRegistry(app_dsn).register(make_record(tmp_path))
    with _owner(app_dsn) as conn:
        for stmt in [
            "UPDATE registry_records SET registered_by = 'x'",
            "DELETE FROM registry_records",
            "DROP TABLE registry_records",
            "ALTER TABLE registry_records DISABLE TRIGGER ALL",
        ]:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute(stmt)  # type: ignore[call-overload]


def test_runtime_role_cannot_migrate(app_dsn: str) -> None:
    with pytest.raises(RegistryBackendError, match="permission denied"):
        PostgresRegistry(app_dsn).migrate()


# -- migrations --------------------------------------------------------------


def test_migrate_is_idempotent(registry: PostgresRegistry) -> None:
    assert registry.migrate() == []


def test_uninitialized_database_is_refused_with_an_actionable_message(pg_template_db: tuple[str, str]) -> None:
    admin, _ = pg_template_db
    name = f"mg_empty_{uuid.uuid4().hex[:8]}"
    with _owner(admin) as conn:
        conn.execute(f'CREATE DATABASE "{name}"')  # type: ignore[call-overload]
    try:
        with pytest.raises(RegistryBackendError, match="not initialized.*migrate"):
            PostgresRegistry(make_conninfo(admin, dbname=name)).get("m", "1")
        assert PostgresRegistry(make_conninfo(admin, dbname=name)).migrate() == [1]
    finally:
        with _owner(admin) as conn:
            conn.execute(f'DROP DATABASE "{name}" WITH (FORCE)')  # type: ignore[call-overload]


def _privileged_edit(dsn: str, sql: str) -> None:
    """Simulate a privileged attacker: owner disables the triggers first."""
    with _owner(dsn) as conn:
        for table in ("registry_records", "revocation_events", "modelguard_schema_migrations"):
            conn.execute(f"ALTER TABLE {table} DISABLE TRIGGER USER")  # type: ignore[call-overload]
        conn.execute(sql)  # type: ignore[call-overload]


def test_altered_migration_checksum_is_refused(pg_dsn: str) -> None:
    _privileged_edit(pg_dsn, "UPDATE modelguard_schema_migrations SET checksum = repeat('0', 64)")
    with pytest.raises(RegistryBackendError, match="checksum mismatch"):
        PostgresRegistry(pg_dsn).get("m", "1")
    with pytest.raises(RegistryBackendError, match="checksum mismatch"):
        PostgresRegistry(pg_dsn).migrate()


def test_database_newer_than_the_code_is_refused(pg_dsn: str) -> None:
    _privileged_edit(
        pg_dsn,
        f"INSERT INTO modelguard_schema_migrations (version, name, checksum) "
        f"VALUES ({LATEST_VERSION + 1}, 'future', repeat('a', 64))",
    )
    with pytest.raises(RegistryBackendError, match="newer than this ModelGuard"):
        PostgresRegistry(pg_dsn).get("m", "1")
    with pytest.raises(RegistryBackendError, match="refusing to migrate"):
        PostgresRegistry(pg_dsn).migrate()


# -- revocation hash chain ---------------------------------------------------


def test_untouched_chain_verifies(registry: PostgresRegistry) -> None:
    registry.verify_revocation_chain()  # empty chain is valid
    _revoke(registry, 4)
    registry.verify_revocation_chain()


def test_edited_event_is_detected(registry: PostgresRegistry, pg_dsn: str) -> None:
    _revoke(registry, 3)
    _privileged_edit(pg_dsn, "UPDATE revocation_events SET reason = 'forged' WHERE reason = 'r1'")
    with pytest.raises(ChainIntegrityError):
        registry.verify_revocation_chain()


def test_deleted_middle_event_is_detected(registry: PostgresRegistry, pg_dsn: str) -> None:
    _revoke(registry, 3)
    _privileged_edit(pg_dsn, "DELETE FROM revocation_events WHERE reason = 'r1'")
    with pytest.raises(ChainIntegrityError):
        registry.verify_revocation_chain()


def test_concurrent_revocations_do_not_fork_the_chain(registry: PostgresRegistry) -> None:
    errors: list[BaseException] = []

    def worker(worker_id: int) -> None:
        try:
            for i in range(5):
                registry.revoke(
                    RevocationRecord(model_id=f"m{worker_id}", version=str(i), revoked_by="s", reason="r")
                )
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    registry.verify_revocation_chain()


# -- stored data is untrusted ------------------------------------------------


def test_corrupted_stored_record_is_refused_not_returned(
    registry: PostgresRegistry, pg_dsn: str, tmp_path: Path
) -> None:
    registry.register(make_record(tmp_path))
    _privileged_edit(pg_dsn, "UPDATE registry_records SET record = '{\"junk\": true}'::jsonb")
    with pytest.raises(RegistryBackendError, match="failed validation"):
        registry.get("demo", "1.0.0")


def test_record_that_disagrees_with_its_indexed_columns_is_refused(
    registry: PostgresRegistry, pg_dsn: str, tmp_path: Path
) -> None:
    registry.register(make_record(tmp_path, content=b"one"))
    other = make_record(tmp_path, "demo", "2.0.0", content=b"two")
    # Swap in a valid record for a different version under the original row's key.
    _privileged_edit(
        pg_dsn,
        "UPDATE registry_records SET record = "
        f"'{other.model_dump_json()}'::jsonb WHERE version = '1.0.0'",
    )
    with pytest.raises(RegistryBackendError, match="disagrees"):
        registry.get("demo", "1.0.0")


# -- fail-closed behavior through the SDK and admission ------------------------


def test_verify_sees_revocations_from_the_postgres_registry(
    pg_dsn: str, signed_model: SignedModel
) -> None:
    registry = PostgresRegistry(pg_dsn)
    guard = ModelGuard(trusted_key_fingerprints=[signed_model.fingerprint], registry=registry)
    args = (signed_model.artifact, signed_model.mbom_path, signed_model.sig_path)

    before = guard.verify(*args)
    assert before.allowed and before.revocation_checked

    registry.revoke(RevocationRecord(model_id="demo", version="1.0.0", revoked_by="sec", reason="bad"))
    after = guard.verify(*args)
    assert after.revoked and not after.allowed


def test_registry_outage_is_never_treated_as_not_revoked(signed_model: SignedModel, tmp_path: Path) -> None:
    dead = PostgresRegistry("host=127.0.0.1 port=1 dbname=mg user=u", connect_timeout_s=1)
    guard = ModelGuard(trusted_key_fingerprints=[signed_model.fingerprint], registry=dead)
    with pytest.raises(RegistryBackendError):
        guard.verify(signed_model.artifact, signed_model.mbom_path, signed_model.sig_path)


def test_admission_denies_when_the_registry_is_down(signed_model: SignedModel) -> None:
    dead = PostgresRegistry("host=127.0.0.1 port=1 dbname=mg user=u", connect_timeout_s=1)
    guard = ModelGuard(trusted_key_fingerprints=[signed_model.fingerprint], registry=dead)
    decision = admit(
        guard,
        signed_model.artifact,
        signed_model.mbom_path,
        signed_model.sig_path,
        signed_model.policy_path,
        actor="deploy-bot",
    )
    assert not decision.admitted
    assert decision.error == "RegistryBackendError"


def test_admission_reports_revoked_via_postgres(pg_dsn: str, signed_model: SignedModel) -> None:
    registry = PostgresRegistry(pg_dsn)
    registry.revoke(RevocationRecord(model_id="demo", version="1.0.0", revoked_by="sec", reason="bad"))
    guard = ModelGuard(trusted_key_fingerprints=[signed_model.fingerprint], registry=registry)
    decision = admit(
        guard,
        signed_model.artifact,
        signed_model.mbom_path,
        signed_model.sig_path,
        signed_model.policy_path,
        actor="deploy-bot",
    )
    assert not decision.admitted and decision.decision == Decision.REVOKED
    assert decision.revocation_checked


def test_wrong_password_reports_auth_failure_without_leaking(pg_dsn: str) -> None:
    bad = PostgresRegistry(make_conninfo(pg_dsn, password="definitely-wrong-pw"))
    with pytest.raises(RegistryBackendError) as exc:
        bad.get("m", "1")
    assert "authentication failed" in str(exc.value)
    assert "definitely-wrong-pw" not in str(exc.value)
