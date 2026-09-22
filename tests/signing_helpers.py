"""Test-only helpers for signature-scheme tests.

``SoftwareP256Signer`` implements the public ``SignerProvider`` protocol
without importing anything private, which doubles as a check that a
third party can write a provider.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from modelguard.manifest.builder import DeclaredMetadata
from modelguard.manifest.models import Manifest
from modelguard.mbom.models import MLBOM
from modelguard.sdk import ModelGuard
from modelguard.signing.envelope import SignatureEnvelope, SignaturePayload
from modelguard.signing.providers import SignerProvider
from modelguard.signing.schemes import ALGORITHM_ECDSA_P256_SHA256


class SoftwareP256Signer:
    def __init__(self, identity: str = "p256@example.com") -> None:
        self._key = ec.generate_private_key(ec.SECP256R1())
        self._identity = identity

    @property
    def algorithm(self) -> str:
        return ALGORITHM_ECDSA_P256_SHA256

    @property
    def identity(self) -> str:
        return self._identity

    def public_key(self) -> bytes:
        return self._key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message, ec.ECDSA(hashes.SHA256()))


@dataclass(frozen=True)
class Model:
    path: Path
    manifest: Manifest
    mbom: MLBOM
    mbom_path: Path


def make_model(root: Path) -> Model:
    root.mkdir(parents=True, exist_ok=True)
    artifact = root / "model"
    artifact.mkdir()
    (artifact / "weights.bin").write_bytes(b"\x01weights" * 32)
    (artifact / "config.json").write_text('{"layers": 2}')
    guard = ModelGuard()
    manifest = guard.build_manifest(
        artifact, DeclaredMetadata(model_id="demo", version="1.0.0", license="Apache-2.0")
    )
    mbom = guard.generate_mbom(manifest)
    mbom_path = root / "model.bom.json"
    mbom_path.write_text(mbom.model_dump_json(indent=2))
    return Model(artifact, manifest, mbom, mbom_path)


def sign_raw(
    payload: SignaturePayload,
    signer: SignerProvider,
    *,
    signature_type: str | None = None,
) -> SignatureEnvelope:
    """Cryptographically valid signature over an arbitrary payload.

    Lets tests build envelopes whose crypto is fine but whose structure
    is hostile, to prove the verifier's structural checks do not depend
    on the signature happening to fail.
    """
    return SignatureEnvelope(
        signature_type=signature_type or signer.algorithm,
        payload=payload,
        signature=signer.sign(payload.canonical_json()).hex(),
        public_key=signer.public_key().hex(),
    )
