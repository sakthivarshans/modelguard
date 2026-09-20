"""CLI wiring for the PostgreSQL registry and object-store commands."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from modelguard.cli.main import cli
from tests.conftest import SignedModel

DSN_ENV = "MG_TEST_REGISTRY_DSN"


def _inv(*args: str, **env: str) -> object:
    return CliRunner().invoke(cli, list(args), env=env)


# -- --registry-dsn-env (fail-closed configuration) --------------------------------


@pytest.mark.parametrize("cmd", [["resolve", "m", "1"], ["revoke", "m", "1", "--actor", "a", "--reason", "r"]])
def test_unset_dsn_env_is_an_error_not_a_fallback_to_local(cmd: list[str], tmp_path: Path) -> None:
    result = CliRunner().invoke(
        cli, [*cmd, "--registry-dsn-env", "MG_DEFINITELY_UNSET", "--storage-root", str(tmp_path / "s")]
    )
    assert result.exit_code == 1
    assert "not set" in result.output and "local registry" in result.output
    assert not (tmp_path / "s" / "registry").exists()  # nothing was silently written locally


def test_verify_with_unset_dsn_env_fails_rather_than_skipping_revocation(signed_model: SignedModel) -> None:
    result = CliRunner().invoke(
        cli,
        ["verify", str(signed_model.artifact), "--mbom", str(signed_model.mbom_path),
         "--signature", str(signed_model.sig_path), "--registry-dsn-env", "MG_DEFINITELY_UNSET"],
    )  # fmt: skip
    assert result.exit_code == 1


def test_dsn_is_never_echoed_on_a_bad_configuration() -> None:
    result = CliRunner().invoke(
        cli,
        ["resolve", "m", "1", "--registry-dsn-env", DSN_ENV],
        env={DSN_ENV: "host=db.example.com dbname=mg user=u password=hunter2-SECRET"},
    )
    assert result.exit_code == 1
    assert "hunter2" not in result.output


def test_unreachable_registry_is_exit_1_with_a_clean_message(signed_model: SignedModel) -> None:
    result = CliRunner().invoke(
        cli,
        ["verify", str(signed_model.artifact), "--mbom", str(signed_model.mbom_path),
         "--signature", str(signed_model.sig_path), "--registry-dsn-env", DSN_ENV],
        env={DSN_ENV: "host=127.0.0.1 port=1 dbname=mg user=u password=hunter2-SECRET"},
    )  # fmt: skip
    assert result.exit_code == 1
    assert "hunter2" not in result.output and "Traceback" not in result.output


# -- against a real PostgreSQL ---------------------------------------------------------


def test_full_registry_workflow_over_postgres(pg_dsn: str, signed_model: SignedModel, tmp_path: Path) -> None:
    pytest.importorskip("psycopg")
    env = {DSN_ENV: pg_dsn}
    runner = CliRunner()

    manifest = tmp_path / "m.json"
    r = runner.invoke(cli, ["manifest", str(signed_model.artifact), "-o", str(manifest),
                            "--model-id", "demo", "--version", "1.0.0", "--license", "Apache-2.0"])  # fmt: skip
    assert r.exit_code == 0, r.output

    reg = runner.invoke(cli, ["register", str(manifest), str(signed_model.mbom_path), "--actor", "dev",
                              "--registry-dsn-env", DSN_ENV, "--storage-root", str(tmp_path / "s")], env=env)  # fmt: skip
    assert reg.exit_code == 0, reg.output

    res = runner.invoke(cli, ["resolve", "demo", "1.0.0", "--registry-dsn-env", DSN_ENV, "--format", "json"], env=env)
    assert res.exit_code == 0 and json.loads(res.output)["revoked"] is False

    verify_args = ["verify", str(signed_model.artifact), "--mbom", str(signed_model.mbom_path),
                   "--signature", str(signed_model.sig_path), "--registry-dsn-env", DSN_ENV,
                   "--trusted-fingerprint", signed_model.fingerprint]  # fmt: skip
    assert runner.invoke(cli, verify_args, env=env).exit_code == 0

    rev = runner.invoke(cli, ["revoke", "demo", "1.0.0", "--actor", "sec", "--reason", "compromised",
                              "--registry-dsn-env", DSN_ENV], env=env)  # fmt: skip
    assert rev.exit_code == 0, rev.output

    after = runner.invoke(cli, verify_args, env=env)
    assert after.exit_code == 2 and "Revoked      : YES" in after.output

    dup = runner.invoke(cli, ["register", str(manifest), str(signed_model.mbom_path), "--actor", "dev",
                              "--registry-dsn-env", DSN_ENV], env=env)  # fmt: skip
    assert dup.exit_code == 1 and "already registered" in dup.output

    chain = runner.invoke(cli, ["registry", "verify-chain", "--dsn-env", DSN_ENV], env=env)
    assert chain.exit_code == 0 and "intact" in chain.output


def test_registry_migrate_command(pg_template_db: tuple[str, str]) -> None:
    import uuid

    import psycopg
    from psycopg.conninfo import make_conninfo

    admin, _ = pg_template_db
    name = f"mg_cli_{uuid.uuid4().hex[:8]}"
    with psycopg.connect(admin, autocommit=True) as conn:
        conn.execute(f'CREATE DATABASE "{name}"')  # type: ignore[call-overload]
    try:
        env = {DSN_ENV: make_conninfo(admin, dbname=name)}
        first = CliRunner().invoke(cli, ["registry", "migrate", "--dsn-env", DSN_ENV], env=env)
        second = CliRunner().invoke(cli, ["registry", "migrate", "--dsn-env", DSN_ENV], env=env)
        assert first.exit_code == 0 and "[1]" in first.output
        assert second.exit_code == 0 and "up to date" in second.output
    finally:
        with psycopg.connect(admin, autocommit=True) as conn:
            conn.execute(f'DROP DATABASE "{name}" WITH (FORCE)')  # type: ignore[call-overload]


def test_verify_chain_reports_tampering_with_exit_2(pg_dsn: str) -> None:
    import psycopg

    from modelguard.registry import RevocationRecord
    from modelguard.registry.postgres import PostgresRegistry

    reg = PostgresRegistry(pg_dsn)
    for i in range(3):
        reg.revoke(RevocationRecord(model_id="m", version=str(i), revoked_by="s", reason=f"r{i}"))
    with psycopg.connect(pg_dsn, autocommit=True) as conn:
        conn.execute("ALTER TABLE revocation_events DISABLE TRIGGER USER")
        conn.execute("UPDATE revocation_events SET reason = 'forged' WHERE reason = 'r1'")
    result = CliRunner().invoke(cli, ["registry", "verify-chain", "--dsn-env", DSN_ENV], env={DSN_ENV: pg_dsn})
    assert result.exit_code == 2 and "TAMPERED" in result.output


# -- artifact push / pull ---------------------------------------------------------------


def _model(tmp_path: Path) -> Path:
    m = tmp_path / "model"
    m.mkdir()
    (m / "w.bin").write_bytes(b"weights" * 1000)
    (m / "cfg.json").write_text("{}")
    return m


def test_artifact_push_pull_roundtrip_local_store(tmp_path: Path) -> None:
    model = _model(tmp_path)
    store = tmp_path / "blobs"
    push = CliRunner().invoke(cli, ["artifact", "push", str(model), "--local-store", str(store)])
    assert push.exit_code == 0, push.output
    digest = push.output.strip().splitlines()[0]
    assert digest.startswith("sha256:")

    out = tmp_path / "restored"
    pull = CliRunner().invoke(cli, ["artifact", "pull", digest, str(out), "--type", "directory", "--local-store", str(store)])
    assert pull.exit_code == 0, pull.output
    assert (out / "w.bin").read_bytes() == b"weights" * 1000


def test_artifact_pull_of_a_tampered_blob_exits_2_and_writes_nothing(tmp_path: Path) -> None:
    model = _model(tmp_path)
    store = tmp_path / "blobs"
    digest = CliRunner().invoke(cli, ["artifact", "push", str(model), "--local-store", str(store)]).output.splitlines()[0]
    for blob in (store / "blobs").rglob("*"):
        if blob.is_file() and blob.stat().st_size == len(b"weights" * 1000):
            blob.write_bytes(b"backdoor" * 875)
    out = tmp_path / "restored"
    pull = CliRunner().invoke(cli, ["artifact", "pull", digest, str(out), "--type", "directory", "--local-store", str(store)])
    assert pull.exit_code == 2
    assert not out.exists()


def test_artifact_store_options_are_mutually_exclusive(tmp_path: Path) -> None:
    model = _model(tmp_path)
    none = CliRunner().invoke(cli, ["artifact", "push", str(model)])
    both = CliRunner().invoke(cli, ["artifact", "push", str(model), "--bucket", "b", "--local-store", str(tmp_path)])
    assert none.exit_code == 1 and both.exit_code == 1


def test_artifact_push_pull_over_s3(tmp_path: Path, moto_endpoint: str, s3_env: None) -> None:
    import uuid

    import boto3

    bucket = f"mg-cli-{uuid.uuid4().hex[:10]}"
    boto3.client("s3", endpoint_url=moto_endpoint, region_name="us-east-1").create_bucket(Bucket=bucket)
    model = _model(tmp_path)
    common = ["--bucket", bucket, "--endpoint-url", moto_endpoint, "--region", "us-east-1", "--prefix", "cli"]

    push = CliRunner().invoke(cli, ["artifact", "push", str(model), *common])
    assert push.exit_code == 0, push.output
    digest = push.output.splitlines()[0]

    out = tmp_path / "restored"
    pull = CliRunner().invoke(cli, ["artifact", "pull", digest, str(out), "--type", "directory", *common])
    assert pull.exit_code == 0, pull.output
    assert (out / "cfg.json").read_text() == "{}"


def test_artifact_push_refuses_insecure_remote_endpoint(tmp_path: Path, s3_env: None) -> None:
    result = CliRunner().invoke(
        cli, ["artifact", "push", str(_model(tmp_path)), "--bucket", "b", "--endpoint-url", "http://s3.example.com"]
    )
    assert result.exit_code == 1 and "non-https" in result.output
