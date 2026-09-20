"""Shared fixtures for tests that need a signed model on disk."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from modelguard.manifest.builder import DeclaredMetadata
from modelguard.sdk import ModelGuard
from modelguard.signing.keys import LocalKeyPair, generate_keypair
from modelguard.signing.trust import public_key_fingerprint

PERMISSIVE_POLICY = "policy:\n  name: permissive\nrules: {}\n"

STRICT_POLICY = """\
policy:
  name: strict
rules:
  require_valid_signature: {enabled: true, on_fail: deny}
  require_trusted_signer: {enabled: true, on_fail: deny}
  require_ml_bom: {enabled: true, on_fail: deny}
  reject_revoked_models: {enabled: true, on_fail: deny}
"""


@dataclass(frozen=True)
class SignedModel:
    artifact: Path
    mbom_path: Path
    sig_path: Path
    keypair: LocalKeyPair
    fingerprint: str
    policy_path: Path


def make_fingerprint(keypair: LocalKeyPair) -> str:
    raw = keypair.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return public_key_fingerprint(raw.hex())


def build_signed_model(
    root: Path, *, name: str = "model", keypair: LocalKeyPair | None = None
) -> SignedModel:
    """Create a small directory artifact, sign it, and write all sidecar files."""
    root.mkdir(parents=True, exist_ok=True)
    artifact = root / name
    artifact.mkdir()
    (artifact / "weights.bin").write_bytes(b"\x00\x01weights" * 64)
    (artifact / "config.json").write_text('{"layers": 2}')

    guard = ModelGuard()
    manifest = guard.build_manifest(
        artifact, DeclaredMetadata(model_id="demo", version="1.0.0", license="Apache-2.0")
    )
    mbom = guard.generate_mbom(manifest)
    signer = keypair or generate_keypair("dev@example.com")
    envelope = guard.sign(manifest, mbom, signer)

    mbom_path = root / f"{name}.bom.json"
    sig_path = root / f"{name}.sig.json"
    mbom_path.write_text(mbom.model_dump_json(indent=2))
    sig_path.write_text(envelope.to_json())
    policy_path = root / f"{name}.policy.yaml"
    policy_path.write_text(STRICT_POLICY)
    return SignedModel(artifact, mbom_path, sig_path, signer, make_fingerprint(signer), policy_path)


@pytest.fixture
def signed_model(tmp_path: Path) -> SignedModel:
    return build_signed_model(tmp_path)


# -- PostgreSQL fixtures -------------------------------------------------
#
# Real PostgreSQL only -- no fakes. Set MODELGUARD_TEST_POSTGRES_DSN to a
# DSN for a role that may CREATE DATABASE (e.g.
# "host=localhost dbname=postgres user=mg_test password=..."). Without it
# every postgres-marked test is SKIPPED (visible in the pytest summary),
# never silently passed.

import os
import uuid
from collections.abc import Iterator

POSTGRES_DSN_ENV = "MODELGUARD_TEST_POSTGRES_DSN"


def _admin_dsn() -> str:
    dsn = os.environ.get(POSTGRES_DSN_ENV)
    if not dsn:
        pytest.skip(f"{POSTGRES_DSN_ENV} is not set; skipping PostgreSQL tests")
    return dsn


@pytest.fixture(scope="session")
def pg_template_db() -> Iterator[tuple[str, str]]:
    """A migrated template database. Yields (admin_dsn, template_name)."""
    psycopg = pytest.importorskip("psycopg")
    from psycopg.conninfo import make_conninfo

    from modelguard.registry.postgres import PostgresRegistry

    admin = _admin_dsn()
    name = f"mg_tpl_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(admin, autocommit=True) as conn:
        conn.execute(f'CREATE DATABASE "{name}"')
    try:
        PostgresRegistry(make_conninfo(admin, dbname=name)).migrate()
        yield admin, name
    finally:
        with psycopg.connect(admin, autocommit=True) as conn:
            conn.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


@pytest.fixture
def pg_dsn(pg_template_db: tuple[str, str]) -> Iterator[str]:
    """A fresh, migrated database per test; yields its DSN."""
    import psycopg
    from psycopg.conninfo import make_conninfo

    admin, template = pg_template_db
    name = f"mg_t_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(admin, autocommit=True) as conn:
        conn.execute(f'CREATE DATABASE "{name}" TEMPLATE "{template}"')
    try:
        yield make_conninfo(admin, dbname=name)
    finally:
        with psycopg.connect(admin, autocommit=True) as conn:
            conn.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


# -- Blob store fixtures (local + S3 via a real moto HTTP server) -------------

import socket
from collections.abc import Callable

from modelguard.storage import BlobStore, LocalBlobStore


@dataclass
class BlobBackend:
    """A blob store plus test-only hooks to tamper with what it holds."""

    store: BlobStore
    tamper: Callable[[str, bytes], None]  # overwrite the stored bytes for a digest
    stored_count: Callable[[], int]


@pytest.fixture(scope="session")
def moto_endpoint() -> Iterator[str]:
    pytest.importorskip("moto")
    from moto.server import ThreadedMotoServer

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = ThreadedMotoServer(ip_address="127.0.0.1", port=port, verbose=False)
    server.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.stop()


@pytest.fixture
def s3_env(monkeypatch: pytest.MonkeyPatch) -> None:
    # Dummy credentials for the throwaway local moto server only.
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@pytest.fixture(params=["local", "s3"])
def blob_backend(request: pytest.FixtureRequest, tmp_path: Path) -> BlobBackend:
    if request.param == "local":
        root = tmp_path / "blobs"
        local = LocalBlobStore(root)

        def tamper_local(sha: str, data: bytes) -> None:
            (root / "blobs" / "sha256" / sha[:2] / sha).write_bytes(data)

        def count_local() -> int:
            return sum(1 for p in root.rglob("*") if p.is_file())

        return BlobBackend(local, tamper_local, count_local)

    import boto3

    from modelguard.storage.s3 import S3BlobStore

    endpoint = request.getfixturevalue("moto_endpoint")
    request.getfixturevalue("s3_env")
    bucket = f"mg-{uuid.uuid4().hex[:12]}"
    raw = boto3.client("s3", endpoint_url=endpoint, region_name="us-east-1")
    raw.create_bucket(Bucket=bucket)
    s3 = S3BlobStore(bucket, prefix="mg", endpoint_url=endpoint, region_name="us-east-1")

    def tamper_s3(sha: str, data: bytes) -> None:
        raw.put_object(Bucket=bucket, Key=f"mg/blobs/sha256/{sha[:2]}/{sha}", Body=data)

    def count_s3() -> int:
        return int(raw.list_objects_v2(Bucket=bucket).get("KeyCount", 0))

    return BlobBackend(s3, tamper_s3, count_s3)
