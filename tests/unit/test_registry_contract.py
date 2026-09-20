"""Behavioral contract every ``Registry`` backend must satisfy.

The same tests run against ``LocalRegistry`` and ``PostgresRegistry``
(the latter skipped, visibly, when no test database is configured).
A behavior that differs between backends is a bug in one of them.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from modelguard.manifest.builder import DeclaredMetadata, build_manifest
from modelguard.mbom.generator import generate_mbom
from modelguard.registry import (
    DuplicateRegistrationError,
    InvalidIdentifierError,
    LocalRegistry,
    Registry,
    RegistryRecord,
    RevocationRecord,
)


def make_record(tmp_path: Path, model_id: str = "demo", version: str = "1.0.0", content: bytes = b"weights") -> RegistryRecord:
    f = tmp_path / f"{abs(hash((model_id, version)))}.bin"
    f.write_bytes(content)
    manifest = build_manifest(f, DeclaredMetadata(model_id=model_id, version=version))
    return RegistryRecord(
        model_id=model_id,
        version=version,
        artifact_digest=f"{manifest.algorithm}:{manifest.digest}",
        manifest=manifest,
        mbom=generate_mbom(manifest),
        registered_by="dev@example.com",
    )


@pytest.fixture(params=["local", "postgres"])
def registry(request: pytest.FixtureRequest, tmp_path: Path) -> Registry:
    if request.param == "local":
        return LocalRegistry(tmp_path / "registry")
    from modelguard.registry.postgres import PostgresRegistry

    return PostgresRegistry(request.getfixturevalue("pg_dsn"))


def test_register_and_get_roundtrip(registry: Registry, tmp_path: Path) -> None:
    record = make_record(tmp_path)
    registry.register(record)
    assert registry.get("demo", "1.0.0") == record


def test_get_missing_returns_none(registry: Registry) -> None:
    assert registry.get("nope", "1") is None
    assert registry.get_by_digest("sha256:" + "0" * 64) is None
    assert registry.list_versions("nope") == []


def test_duplicate_model_version_is_rejected_and_original_kept(registry: Registry, tmp_path: Path) -> None:
    original = make_record(tmp_path, content=b"original")
    registry.register(original)
    with pytest.raises(DuplicateRegistrationError):
        registry.register(make_record(tmp_path, content=b"different bytes"))
    assert registry.get("demo", "1.0.0") == original


def test_get_by_digest_resolves(registry: Registry, tmp_path: Path) -> None:
    record = make_record(tmp_path)
    registry.register(record)
    assert registry.get_by_digest(record.artifact_digest) == record


def test_same_digest_under_second_name_does_not_repoint_the_first(registry: Registry, tmp_path: Path) -> None:
    """Names are mutable, digests are not: first registration wins."""
    first = make_record(tmp_path, "team-a", "1", content=b"same bytes")
    second = make_record(tmp_path, "team-b", "9", content=b"same bytes")
    assert first.artifact_digest == second.artifact_digest
    registry.register(first)
    registry.register(second)
    resolved = registry.get_by_digest(first.artifact_digest)
    assert resolved is not None and (resolved.model_id, resolved.version) == ("team-a", "1")


def test_list_versions_is_sorted_and_scoped_to_the_model(registry: Registry, tmp_path: Path) -> None:
    for model_id, version in [("m", "2.0"), ("m", "1.0"), ("m", "10.0"), ("other", "1.0")]:
        registry.register(make_record(tmp_path, model_id, version, content=f"{model_id}{version}".encode()))
    assert registry.list_versions("m") == ["1.0", "10.0", "2.0"]


def test_revoke_and_unrevoke(registry: Registry, tmp_path: Path) -> None:
    registry.register(make_record(tmp_path, "m", "1", content=b"a"))
    registry.register(make_record(tmp_path, "m", "2", content=b"b"))
    assert registry.is_revoked("m", "1") is None

    registry.revoke(RevocationRecord(model_id="m", version="1", revoked_by="sec", reason="compromised"))
    revoked = registry.is_revoked("m", "1")
    assert revoked is not None and revoked.reason == "compromised" and revoked.revoked_by == "sec"
    assert registry.is_revoked("m", "2") is None  # other versions unaffected

    registry.unrevoke("m", "1", actor="sec", reason="false positive")
    assert registry.is_revoked("m", "1") is None
    registry.revoke(RevocationRecord(model_id="m", version="1", revoked_by="sec", reason="again"))
    assert registry.is_revoked("m", "1") is not None


def test_revoking_an_unregistered_version_is_allowed(registry: Registry) -> None:
    registry.revoke(RevocationRecord(model_id="ghost", version="1", revoked_by="sec", reason="preemptive"))
    assert registry.is_revoked("ghost", "1") is not None


BAD_IDS = ["", ".", "..", "../x", "a/b", "a\\b", "x\x00y", "line\nbreak", " lead", "trail ", "e\u0301", "a" * 201]


@pytest.mark.parametrize("bad", BAD_IDS)
def test_every_operation_rejects_unsafe_identifiers(registry: Registry, tmp_path: Path, bad: str) -> None:
    with pytest.raises(InvalidIdentifierError):
        registry.get(bad, "1")
    with pytest.raises(InvalidIdentifierError):
        registry.get("m", bad)
    with pytest.raises(InvalidIdentifierError):
        registry.list_versions(bad)
    with pytest.raises(InvalidIdentifierError):
        registry.is_revoked(bad, "1")
    with pytest.raises(InvalidIdentifierError):
        registry.revoke(RevocationRecord(model_id=bad, version="1", revoked_by="s", reason="r"))
    with pytest.raises(InvalidIdentifierError):
        registry.unrevoke("m", bad, actor="s", reason="r")


def test_unsafe_identifier_cannot_be_registered(registry: Registry, tmp_path: Path) -> None:
    record = make_record(tmp_path, "safe", "1").model_copy(update={"model_id": "../escape"})
    with pytest.raises(InvalidIdentifierError):
        registry.register(record)


def test_sql_metacharacters_are_plain_data(registry: Registry, tmp_path: Path) -> None:
    nasty = "x'); DROP TABLE registry_records;--"
    record = make_record(tmp_path, nasty, "1")
    registry.register(record)
    assert registry.get(nasty, "1") == record
    registry.revoke(RevocationRecord(model_id=nasty, version="1", revoked_by="s'; --", reason="\"; DELETE"))
    assert registry.is_revoked(nasty, "1") is not None
    # The registry is still intact and usable afterwards.
    other = make_record(tmp_path, "after", "1", content=b"after")
    registry.register(other)
    assert registry.get("after", "1") == other


def test_malformed_artifact_digest_cannot_be_constructed() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        RegistryRecord.model_validate(
            {
                "model_id": "m",
                "version": "1",
                "artifact_digest": "sha256:abc",
                "manifest": {},
                "mbom": {},
                "registered_by": "x",
            }
        )
