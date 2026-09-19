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
