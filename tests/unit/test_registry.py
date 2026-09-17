from __future__ import annotations

from pathlib import Path

import pytest

from modelguard.exceptions import ModelGuardError
from modelguard.manifest.builder import DeclaredMetadata, build_manifest
from modelguard.mbom.generator import generate_mbom
from modelguard.registry.local import DuplicateRegistrationError, LocalRegistry
from modelguard.registry.models import RegistryRecord, RevocationRecord


def _record(tmp_path: Path, model_id: str = "demo", version: str = "1.0.0") -> RegistryRecord:
    f = tmp_path / f"{model_id}-{version}.bin"
    f.write_bytes(b"weights")
    manifest = build_manifest(f, DeclaredMetadata(model_id=model_id, version=version))
    bom = generate_mbom(manifest)
    return RegistryRecord(
        model_id=model_id,
        version=version,
        artifact_digest=f"{manifest.algorithm}:{manifest.digest}",
        manifest=manifest,
        mbom=bom,
        registered_by="dev@example.com",
    )


def test_register_and_get(tmp_path: Path) -> None:
    registry = LocalRegistry(tmp_path / "registry")
    record = _record(tmp_path)

    registry.register(record)
    fetched = registry.get("demo", "1.0.0")

    assert fetched is not None
    assert fetched.artifact_digest == record.artifact_digest


def test_get_missing_returns_none(tmp_path: Path) -> None:
    registry = LocalRegistry(tmp_path / "registry")
    assert registry.get("nope", "1.0.0") is None


def test_get_by_digest(tmp_path: Path) -> None:
    registry = LocalRegistry(tmp_path / "registry")
    record = _record(tmp_path)
    registry.register(record)

    fetched = registry.get_by_digest(record.artifact_digest)

    assert fetched is not None
    assert fetched.model_id == "demo"


def test_duplicate_registration_is_rejected(tmp_path: Path) -> None:
    """A registry must not let a model_id@version silently start
    pointing at a different artifact digest -- this is the namespace
    confusion threat from the threat model.
    """
    registry = LocalRegistry(tmp_path / "registry")
    record = _record(tmp_path)
    registry.register(record)

    with pytest.raises(DuplicateRegistrationError):
        registry.register(record)


def test_list_versions(tmp_path: Path) -> None:
    registry = LocalRegistry(tmp_path / "registry")
    registry.register(_record(tmp_path, "demo", "1.0.0"))
    registry.register(_record(tmp_path, "demo", "2.0.0"))

    assert registry.list_versions("demo") == ["1.0.0", "2.0.0"]
    assert registry.list_versions("unknown-model") == []


def test_revoke_and_is_revoked(tmp_path: Path) -> None:
    registry = LocalRegistry(tmp_path / "registry")
    registry.register(_record(tmp_path))

    assert registry.is_revoked("demo", "1.0.0") is None

    registry.revoke(
        RevocationRecord(
            model_id="demo",
            version="1.0.0",
            revoked_by="security@example.com",
            reason="compromised training data",
        )
    )

    revocation = registry.is_revoked("demo", "1.0.0")
    assert revocation is not None
    assert revocation.reason == "compromised training data"


def test_unrevoke_clears_revocation_but_keeps_history(tmp_path: Path) -> None:
    registry = LocalRegistry(tmp_path / "registry")
    registry.register(_record(tmp_path))
    registry.revoke(
        RevocationRecord(
            model_id="demo", version="1.0.0", revoked_by="a@example.com", reason="mistake"
        )
    )
    assert registry.is_revoked("demo", "1.0.0") is not None

    registry.unrevoke("demo", "1.0.0", actor="a@example.com", reason="revocation was in error")

    assert registry.is_revoked("demo", "1.0.0") is None
    # History persists in the underlying hash-chained log.
    from modelguard.audit.chain import read_all_entries

    entries = read_all_entries(tmp_path / "registry" / "revocations.log.jsonl")
    assert len(entries) == 2


# --------------------------------------------------------------------------
# Security tests
# --------------------------------------------------------------------------


def test_path_traversal_in_model_id_is_rejected(tmp_path: Path) -> None:
    registry = LocalRegistry(tmp_path / "registry")
    record = _record(tmp_path, model_id="../../etc", version="1.0.0")

    with pytest.raises(ModelGuardError):
        registry.register(record)


def test_path_traversal_in_version_is_rejected(tmp_path: Path) -> None:
    registry = LocalRegistry(tmp_path / "registry")
    record = _record(tmp_path, model_id="demo", version="safe-version").model_copy(
        update={"version": "../../../etc/passwd"}
    )

    with pytest.raises(ModelGuardError):
        registry.register(record)
