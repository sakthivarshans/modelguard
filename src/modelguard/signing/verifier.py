"""Ed25519 signature verification and artifact tamper detection.

This module implements the security-critical comparison at the heart
of ModelGuard: does the artifact on disk right now match what was
signed? It deliberately keeps the check simple and inspectable rather
than folding it into a larger pipeline, since a bug here would defeat
the framework's central guarantee.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from modelguard.exceptions import DigestMismatchError, SignatureInvalidError
from modelguard.hashing.digest import hash_artifact
from modelguard.mbom.models import MLBOM
from modelguard.signing.envelope import SignatureEnvelope


@dataclass(frozen=True, slots=True)
class TamperCheckResult:
    """Result of re-hashing an artifact and comparing to a signed digest."""

    current_digest: str
    signed_digest: str
    matches: bool


def check_signature_bytes(envelope: SignatureEnvelope) -> None:
    """Verify the cryptographic signature over the payload.

    Raises ``SignatureInvalidError`` if the signature does not verify
    against the embedded public key. This function does NOT check
    whether that public key is trusted -- that is a policy decision,
    not a cryptography one (Phase 3 adds trust-root configuration).
    """
    try:
        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(envelope.public_key))
        public_key.verify(
            bytes.fromhex(envelope.signature),
            envelope.payload.canonical_json(),
        )
    except InvalidSignature as exc:
        raise SignatureInvalidError(
            "Signature does not match the signed payload. The payload or "
            "signature bytes may have been altered, or the wrong public "
            "key was supplied."
        ) from exc
    except ValueError as exc:
        raise SignatureInvalidError(f"Malformed signature or key data: {exc}") from exc


def check_artifact_digest(artifact_path: Path, envelope: SignatureEnvelope) -> TamperCheckResult:
    """Re-hash the artifact on disk and compare it to the signed digest."""
    current = hash_artifact(artifact_path)
    current_ref = f"{current.algorithm}:{current.digest}"
    return TamperCheckResult(
        current_digest=current_ref,
        signed_digest=envelope.payload.artifact_digest,
        matches=current_ref == envelope.payload.artifact_digest,
    )


def check_mbom_digest(mbom: MLBOM, envelope: SignatureEnvelope) -> bool:
    """Check that a given ML-BOM matches the digest bound into the signature."""
    computed = f"sha256:{hashlib.sha256(mbom.canonical_json()).hexdigest()}"
    return computed == envelope.payload.mbom_digest


def verify_artifact(
    artifact_path: Path,
    mbom: MLBOM,
    envelope: SignatureEnvelope,
) -> TamperCheckResult:
    """Full local verification: signature validity + digest match.

    Fails closed: any check that fails raises immediately rather than
    returning a partial or "best effort" result. Callers that want a
    non-raising structured result should use the SDK's ``verify()``,
    which catches these exceptions and turns them into a
    ``VerificationResult`` with ``allowed=False``.
    """
    check_signature_bytes(envelope)

    if not check_mbom_digest(mbom, envelope):
        raise SignatureInvalidError(
            "The supplied ML-BOM does not match the mbom_digest bound in the "
            "signature. Either the wrong ML-BOM file was supplied, or the "
            "ML-BOM was modified after signing."
        )

    tamper_result = check_artifact_digest(artifact_path, envelope)
    if not tamper_result.matches:
        raise DigestMismatchError(
            expected=tamper_result.signed_digest,
            actual=tamper_result.current_digest,
        )

    return tamper_result
