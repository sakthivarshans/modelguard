"""DSN policy and secret-handling tests (no database needed)."""

from __future__ import annotations

import pytest

pytest.importorskip("psycopg")

from modelguard.registry import RegistryBackendError
from modelguard.registry.errors import RegistryConfigurationError
from modelguard.registry.postgres import PostgresRegistry

REMOTE = "host=db.example.com dbname=mg user=app password=hunter2-SECRET"


@pytest.mark.parametrize("extra", ["", " sslmode=disable", " sslmode=prefer", " sslmode=require"])
def test_remote_host_without_verifying_tls_is_refused(extra: str) -> None:
    with pytest.raises(RegistryConfigurationError, match="verify-full"):
        PostgresRegistry(REMOTE + extra)


@pytest.mark.parametrize("mode", ["verify-full", "verify-ca"])
def test_remote_host_with_verifying_tls_is_accepted(mode: str) -> None:
    PostgresRegistry(f"{REMOTE} sslmode={mode}")


@pytest.mark.parametrize(
    "dsn",
    [
        "host=localhost dbname=mg user=u",
        "host=127.0.0.1 dbname=mg",
        "host=::1 dbname=mg",
        "host=/var/run/postgresql dbname=mg",
    ],
)
def test_local_hosts_do_not_require_tls(dsn: str) -> None:
    PostgresRegistry(dsn)


def test_any_remote_host_in_a_multi_host_dsn_triggers_the_tls_rule() -> None:
    with pytest.raises(RegistryConfigurationError):
        PostgresRegistry("host=localhost,evil.example.com dbname=mg")


def test_dsn_without_explicit_host_is_refused() -> None:
    with pytest.raises(RegistryConfigurationError, match="host explicitly"):
        PostgresRegistry("dbname=mg user=u")


def test_malformed_dsn_is_refused_without_echoing_it() -> None:
    with pytest.raises(RegistryConfigurationError) as exc:
        PostgresRegistry("this is not a dsn password=topsecret")
    assert "topsecret" not in str(exc.value)


def test_insecure_transport_requires_explicit_opt_in() -> None:
    PostgresRegistry(REMOTE, allow_insecure_transport=True)


def test_repr_never_contains_the_dsn() -> None:
    assert "hunter2" not in repr(PostgresRegistry(f"{REMOTE} sslmode=verify-full"))


def test_unreachable_server_raises_backend_error_without_leaking_secrets() -> None:
    registry = PostgresRegistry(
        "host=127.0.0.1 port=1 dbname=mg user=app password=hunter2-SECRET", connect_timeout_s=1
    )
    with pytest.raises(RegistryBackendError) as exc:
        registry.get("m", "1")
    text = str(exc.value)
    assert "could not connect" in text
    assert "hunter2" not in text and "password" not in text
