from __future__ import annotations

from pathlib import Path

from modelguard import ModelGuard
from modelguard.manifest.builder import DeclaredMetadata
from modelguard.mbom.generator import DeclaredProvenance
from modelguard.policy.models import Decision
from modelguard.signing.keys import generate_keypair


def _signed_fixture(
    tmp_path: Path,
    *,
    license_: str | None = None,
    parent_models: list[str] | None = None,
) -> tuple[Path, Path, Path]:
    guard = ModelGuard()
    artifact = tmp_path / "model.bin"
    artifact.write_bytes(b"weights")

    manifest = guard.build_manifest(
        artifact, DeclaredMetadata(model_id="demo", version="1.0.0", license=license_)
    )
    bom = guard.generate_mbom(
        manifest, DeclaredProvenance(parent_models=parent_models or [], license=license_)
    )
    keypair = generate_keypair("dev@example.com")
    envelope = guard.sign(manifest, bom, keypair)

    mbom_path = tmp_path / "model.bom.json"
    mbom_path.write_text(bom.to_json())
    sig_path = tmp_path / "model.sig.json"
    sig_path.write_text(envelope.to_json())

    return artifact, mbom_path, sig_path


def _policy(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(text)
    return path


def test_check_policy_allows_when_everything_present(tmp_path: Path) -> None:
    artifact, mbom_path, sig_path = _signed_fixture(
        tmp_path, license_="Apache-2.0", parent_models=["base@sha256:abc"]
    )
    policy_path = _policy(
        tmp_path,
        """
        policy:
          name: strict
        rules:
          require_valid_signature: {enabled: true, on_fail: deny}
          require_ml_bom: {enabled: true, on_fail: deny}
          require_license: {enabled: true, on_fail: deny}
          require_known_lineage: {enabled: true, on_fail: deny}
        """,
    )

    guard = ModelGuard()
    result = guard.check_policy(artifact, mbom_path, sig_path, policy_path)

    assert result.decision == Decision.ALLOW


def test_check_policy_denies_missing_license(tmp_path: Path) -> None:
    artifact, mbom_path, sig_path = _signed_fixture(tmp_path, license_=None)
    policy_path = _policy(
        tmp_path,
        """
        policy:
          name: strict
        rules:
          require_license: {enabled: true, on_fail: deny}
        """,
    )

    guard = ModelGuard()
    result = guard.check_policy(artifact, mbom_path, sig_path, policy_path)

    assert result.decision == Decision.DENY
    assert any(r.rule == "require_license" for r in result.failed_rules)


def test_check_policy_reflects_tampered_artifact_as_denial(tmp_path: Path) -> None:
    artifact, mbom_path, sig_path = _signed_fixture(tmp_path)
    policy_path = _policy(
        tmp_path,
        """
        policy:
          name: strict
        rules:
          require_valid_signature: {enabled: true, on_fail: deny}
        """,
    )
    artifact.write_bytes(b"tampered")

    guard = ModelGuard()
    result = guard.check_policy(artifact, mbom_path, sig_path, policy_path)

    # Regression (found in Phase 5): before 0.5.0 this returned ALLOW,
    # because signature_valid stays True for a tampered artifact (the
    # signature bytes are still valid) and no rule looked at the digest.
    # Integrity is now an unconditional gate, not a policy rule.
    assert result.decision == Decision.DENY
    assert [r.rule for r in result.failed_rules] == ["artifact_integrity"]


def test_tampered_artifact_is_denied_even_by_an_empty_policy(tmp_path: Path) -> None:
    artifact, mbom_path, sig_path = _signed_fixture(tmp_path)
    policy_path = _policy(tmp_path, "policy:\n  name: permissive\nrules: {}\n")
    artifact.write_bytes(b"tampered")

    result = ModelGuard().check_policy(artifact, mbom_path, sig_path, policy_path)

    assert result.decision == Decision.DENY


def test_check_policy_denies_revoked_model_regardless_of_configured_rules(tmp_path: Path) -> None:
    storage_root = tmp_path / ".modelguard"
    guard = ModelGuard(storage_root=storage_root)
    artifact, mbom_path, sig_path = _signed_fixture(tmp_path)

    manifest = guard.build_manifest(artifact, DeclaredMetadata(model_id="demo", version="1.0.0"))
    import json

    from modelguard.mbom.models import MLBOM

    bom = MLBOM.model_validate(json.loads(mbom_path.read_text()))
    guard.register(manifest, bom, actor="dev@example.com")
    guard.revoke("demo", "1.0.0", actor="security@example.com", reason="compromised")

    policy_path = _policy(
        tmp_path,
        """
        policy:
          name: minimal
        rules:
          reject_revoked_models: {enabled: true, on_fail: warn}
        """,
    )

    result = guard.check_policy(artifact, mbom_path, sig_path, policy_path)

    assert result.decision == Decision.REVOKED


# -- Phase 4: scanning wired into check_policy() -----------------------


def test_check_policy_denies_when_scan_finds_a_critical_secret(tmp_path: Path) -> None:
    guard = ModelGuard()
    artifact_dir = tmp_path / "model"
    artifact_dir.mkdir()
    (artifact_dir / "weights.bin").write_bytes(b"weights")
    (artifact_dir / "leaked.txt").write_text("AKIAABCDEFGHIJKLMNOP")

    manifest = guard.build_manifest(
        artifact_dir, DeclaredMetadata(model_id="demo", version="1.0.0")
    )
    bom = guard.generate_mbom(manifest)
    keypair = generate_keypair("dev@example.com")
    envelope = guard.sign(manifest, bom, keypair)

    mbom_path = tmp_path / "model.bom.json"
    mbom_path.write_text(bom.to_json())
    sig_path = tmp_path / "model.sig.json"
    sig_path.write_text(envelope.to_json())

    policy_path = _policy(
        tmp_path,
        """
        policy:
          name: strict
        rules:
          max_critical_findings: {enabled: true, on_fail: deny, max_count: 0}
        """,
    )

    result = guard.check_policy(artifact_dir, mbom_path, sig_path, policy_path)

    assert result.decision == Decision.DENY
    assert any(r.rule == "max_critical_findings" for r in result.failed_rules)


def test_check_policy_allows_same_policy_without_the_offending_file(tmp_path: Path) -> None:
    """Same policy, same directory structure, but no .pkl/secret file --
    the count-based rule must ALLOW rather than deny by default.
    """
    guard = ModelGuard()
    artifact_dir = tmp_path / "model"
    artifact_dir.mkdir()
    (artifact_dir / "weights.safetensors").write_bytes(b"weights")

    manifest = guard.build_manifest(
        artifact_dir, DeclaredMetadata(model_id="demo", version="1.0.0")
    )
    bom = guard.generate_mbom(manifest)
    keypair = generate_keypair("dev@example.com")
    envelope = guard.sign(manifest, bom, keypair)

    mbom_path = tmp_path / "model.bom.json"
    mbom_path.write_text(bom.to_json())
    sig_path = tmp_path / "model.sig.json"
    sig_path.write_text(envelope.to_json())

    policy_path = _policy(
        tmp_path,
        """
        policy:
          name: strict
        rules:
          max_critical_findings: {enabled: true, on_fail: deny, max_count: 0}
          max_high_findings: {enabled: true, on_fail: deny, max_count: 0}
        """,
    )

    result = guard.check_policy(artifact_dir, mbom_path, sig_path, policy_path)

    assert result.decision == Decision.ALLOW
