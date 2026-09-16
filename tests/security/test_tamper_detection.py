"""End-to-end security tests through the public SDK: a modified artifact,
an invalid signature, or a mismatched ML-BOM must all result in
``VerificationResult.allowed is False`` with an explanatory reason --
never a silent pass and never an unhandled exception for expected
failure modes.
"""

from __future__ import annotations

import json
from pathlib import Path

from modelguard import ModelGuard
from modelguard.manifest.builder import DeclaredMetadata
from modelguard.mbom.generator import generate_mbom
from modelguard.signing.keys import generate_keypair


def _sign_fixture(tmp_path: Path) -> tuple[Path, Path, Path]:
    guard = ModelGuard()
    artifact = tmp_path / "model.bin"
    artifact.write_bytes(b"trustworthy weights")

    manifest = guard.build_manifest(artifact, DeclaredMetadata(model_id="demo"))
    bom = guard.generate_mbom(manifest)
    keypair = generate_keypair("dev@example.com")
    envelope = guard.sign(manifest, bom, keypair)

    mbom_path = tmp_path / "model.bom.json"
    mbom_path.write_text(bom.to_json())
    sig_path = tmp_path / "model.sig.json"
    sig_path.write_text(envelope.to_json())

    return artifact, mbom_path, sig_path


def test_verify_allows_untampered_signed_artifact(tmp_path: Path) -> None:
    artifact, mbom_path, sig_path = _sign_fixture(tmp_path)
    guard = ModelGuard()

    result = guard.verify(artifact, mbom_path, sig_path)

    assert result.allowed
    assert result.signature_valid
    assert result.mbom_valid
    result.raise_if_denied()  # must not raise


def test_verify_denies_tampered_artifact(tmp_path: Path) -> None:
    artifact, mbom_path, sig_path = _sign_fixture(tmp_path)
    artifact.write_bytes(b"malicious substituted weights")

    guard = ModelGuard()
    result = guard.verify(artifact, mbom_path, sig_path)

    assert not result.allowed
    assert result.signature_valid  # signature itself is still cryptographically valid
    assert any("digest mismatch" in r.lower() for r in result.reasons)


def test_verify_denies_corrupted_signature_file(tmp_path: Path) -> None:
    artifact, mbom_path, sig_path = _sign_fixture(tmp_path)

    envelope_data = json.loads(sig_path.read_text())
    envelope_data["signature"] = "00" * 64  # replace with garbage bytes of the right shape
    sig_path.write_text(json.dumps(envelope_data))

    guard = ModelGuard()
    result = guard.verify(artifact, mbom_path, sig_path)

    assert not result.allowed
    assert not result.signature_valid


def test_verify_denies_mismatched_mbom(tmp_path: Path) -> None:
    artifact, mbom_path, sig_path = _sign_fixture(tmp_path)

    guard = ModelGuard()
    manifest = guard.build_manifest(artifact, DeclaredMetadata(model_id="different"))
    unrelated_bom = generate_mbom(manifest)
    mbom_path.write_text(unrelated_bom.to_json())

    result = guard.verify(artifact, mbom_path, sig_path)

    assert not result.allowed
    assert not result.mbom_valid


def test_verification_denied_exception_lists_reasons(tmp_path: Path) -> None:
    from modelguard.exceptions import VerificationDenied

    artifact, mbom_path, sig_path = _sign_fixture(tmp_path)
    artifact.write_bytes(b"tampered")

    guard = ModelGuard()
    result = guard.verify(artifact, mbom_path, sig_path)

    try:
        result.raise_if_denied()
        assert False, "expected VerificationDenied"
    except VerificationDenied as exc:
        assert len(exc.reasons) > 0
