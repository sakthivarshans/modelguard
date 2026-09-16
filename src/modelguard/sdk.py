"""High-level ``ModelGuard`` SDK facade.

This module implements the beginner-friendly API:

    from modelguard import ModelGuard

    guard = ModelGuard()
    result = guard.verify("./models/my-model", public_key_path="key.modelguard.pub")
    result.raise_if_denied()

Advanced users should import from the submodules directly
(``modelguard.hashing``, ``modelguard.mbom``, ``modelguard.signing``)
rather than through this facade.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from modelguard.exceptions import ModelGuardError, VerificationDenied
from modelguard.hashing.digest import ArtifactDigest, hash_artifact
from modelguard.manifest.builder import DeclaredMetadata, build_manifest
from modelguard.manifest.models import Manifest
from modelguard.mbom.generator import DeclaredProvenance, generate_mbom
from modelguard.mbom.models import MLBOM
from modelguard.signing.envelope import SignatureEnvelope
from modelguard.signing.keys import LocalKeyPair, load_public_key
from modelguard.signing.signer import sign_artifact
from modelguard.signing.verifier import (
    check_artifact_digest,
    check_mbom_digest,
    check_signature_bytes,
)


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """Structured outcome of ``ModelGuard.verify()``.

    ``allowed`` reflects Phase 1's scope only: valid signature + digest
    match against the supplied public key and ML-BOM. It does not yet
    reflect policy evaluation, revocation, or scanning -- those are
    added in later phases and will be additional fields here, not a
    change to this field's meaning.
    """

    allowed: bool
    artifact_digest: str
    signature_valid: bool
    mbom_valid: bool
    reasons: tuple[str, ...] = field(default_factory=tuple)

    def raise_if_denied(self) -> None:
        if not self.allowed:
            raise VerificationDenied(list(self.reasons))


class ModelGuard:
    """Primary entry point for the ModelGuard Python SDK."""

    def inspect(self, artifact_path: str | Path) -> ArtifactDigest:
        """Hash and inspect a local artifact without signing or verifying it."""
        return hash_artifact(Path(artifact_path))

    def build_manifest(
        self, artifact_path: str | Path, metadata: DeclaredMetadata | None = None
    ) -> Manifest:
        return build_manifest(Path(artifact_path), metadata)

    def generate_mbom(
        self, manifest: Manifest, provenance: DeclaredProvenance | None = None
    ) -> MLBOM:
        return generate_mbom(manifest, provenance)

    def sign(self, manifest: Manifest, mbom: MLBOM, keypair: LocalKeyPair) -> SignatureEnvelope:
        return sign_artifact(manifest, mbom, keypair)

    def verify(
        self,
        artifact_path: str | Path,
        mbom_path: str | Path,
        signature_path: str | Path,
    ) -> VerificationResult:
        """Verify a previously signed artifact against its ML-BOM and
        detached signature.

        This never raises for an expected verification failure (invalid
        signature, tampered artifact, mismatched ML-BOM); those become
        ``allowed=False`` with an explanatory reason. It only raises for
        unexpected conditions such as a missing file.
        """
        path = Path(artifact_path)
        mbom = MLBOM.model_validate(json.loads(Path(mbom_path).read_text()))
        envelope = SignatureEnvelope.model_validate(
            json.loads(Path(signature_path).read_text())
        )

        reasons: list[str] = []

        signature_valid = True
        try:
            check_signature_bytes(envelope)
        except ModelGuardError as exc:
            signature_valid = False
            reasons.append(str(exc))

        mbom_valid = check_mbom_digest(mbom, envelope)
        if not mbom_valid:
            reasons.append(
                "The supplied ML-BOM does not match the mbom_digest bound in "
                "the signature."
            )

        try:
            tamper_result = check_artifact_digest(path, envelope)
            digest_matches = tamper_result.matches
            current_digest = tamper_result.current_digest
            if not digest_matches:
                reasons.append(
                    f"Artifact digest mismatch: expected {tamper_result.signed_digest}, "
                    f"got {tamper_result.current_digest}. The artifact may have been "
                    "modified after signing."
                )
        except ModelGuardError as exc:
            digest_matches = False
            current_digest = envelope.payload.artifact_digest
            reasons.append(str(exc))

        allowed = signature_valid and mbom_valid and digest_matches

        return VerificationResult(
            allowed=allowed,
            artifact_digest=current_digest,
            signature_valid=signature_valid,
            mbom_valid=mbom_valid,
            reasons=tuple(reasons),
        )

    def load_public_key(self, path: str | Path) -> Ed25519PublicKey:
        return load_public_key(Path(path))
