from __future__ import annotations

from pathlib import Path

from modelguard import ModelGuard
from modelguard.manifest.builder import DeclaredMetadata


def test_sdk_register_and_resolve(tmp_path: Path) -> None:
    guard = ModelGuard(storage_root=tmp_path / ".modelguard")
    artifact = tmp_path / "model.bin"
    artifact.write_bytes(b"weights")

    manifest = guard.build_manifest(artifact, DeclaredMetadata(model_id="demo", version="1.0.0"))
    bom = guard.generate_mbom(manifest)
    record = guard.register(manifest, bom, actor="dev@example.com")

    assert guard.resolve("demo", "1.0.0") == record
    assert guard.resolve_by_digest(record.artifact_digest) == record


def test_sdk_lineage_end_to_end(tmp_path: Path) -> None:
    guard = ModelGuard(storage_root=tmp_path / ".modelguard")
    guard.record_provenance("fine-tuned", "FINE_TUNED_FROM", "base", actor="dev@example.com")
    guard.record_provenance("quantized", "QUANTIZED_FROM", "fine-tuned", actor="dev@example.com")

    assert guard.find_models_derived_from("base") == ["fine-tuned", "quantized"]
    assert {e.object_id for e in guard.lineage("quantized")} == {"fine-tuned", "base"}


def test_sdk_requires_storage_root_for_registry_operations() -> None:
    guard = ModelGuard()  # no storage_root

    from modelguard.exceptions import ModelGuardError

    try:
        guard.resolve("demo", "1.0.0")
        assert False, "expected ModelGuardError"
    except ModelGuardError as exc:
        assert "storage_root" in str(exc)


def test_verify_denies_revoked_model_even_with_valid_signature(tmp_path: Path) -> None:
    """This is the key integration point between Phase 1 (signing) and
    Phase 2 (registry): a revoked model must fail verification even
    though its signature and digest are still perfectly valid.
    """
    storage_root = tmp_path / ".modelguard"
    guard = ModelGuard(storage_root=storage_root)

    artifact = tmp_path / "model.bin"
    artifact.write_bytes(b"weights")
    manifest = guard.build_manifest(artifact, DeclaredMetadata(model_id="demo", version="1.0.0"))
    bom = guard.generate_mbom(manifest)

    from modelguard.signing.keys import generate_keypair

    keypair = generate_keypair("dev@example.com")
    envelope = guard.sign(manifest, bom, keypair)

    mbom_path = tmp_path / "model.bom.json"
    mbom_path.write_text(bom.to_json())
    sig_path = tmp_path / "model.sig.json"
    sig_path.write_text(envelope.to_json())

    guard.register(manifest, bom, actor="dev@example.com")

    # Before revocation: allowed.
    result = guard.verify(artifact, mbom_path, sig_path)
    assert result.allowed
    assert not result.revoked

    # After revocation: denied, even though nothing about the artifact
    # or signature changed.
    guard.revoke("demo", "1.0.0", actor="security@example.com", reason="compromised base model")
    result = guard.verify(artifact, mbom_path, sig_path)

    assert not result.allowed
    assert result.revoked
    assert result.signature_valid  # cryptography is still fine
    assert any("revoked" in r.lower() for r in result.reasons)


def test_find_deployments_using_revoked_model_via_sdk(tmp_path: Path) -> None:
    storage_root = tmp_path / ".modelguard"
    guard = ModelGuard(storage_root=storage_root)

    artifact = tmp_path / "model.bin"
    artifact.write_bytes(b"weights")
    manifest = guard.build_manifest(artifact, DeclaredMetadata(model_id="base", version="1.0.0"))
    bom = guard.generate_mbom(manifest)
    guard.register(manifest, bom, actor="dev@example.com")
    guard.revoke("base", "1.0.0", actor="security@example.com", reason="bad data")

    guard.record_provenance("base", "DEPLOYED_TO", "prod-cluster", actor="ops@example.com")

    flagged = guard.find_deployments_using_revoked_model()
    assert any(e.object_id == "prod-cluster" for e in flagged)
