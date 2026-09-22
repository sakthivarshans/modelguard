"""Ed25519 signature verification and artifact tamper detection.

This module implements the security-critical comparison at the heart
of ModelGuard: does the artifact on disk right now match what was
signed? It deliberately keeps the check simple and inspectable rather
than folding it into a larger pipeline, since a bug here would defeat
the framework's central guarantee.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from modelguard.exceptions import (
    DigestMismatchError,
    SignatureInvalidError,
    UnsupportedSignatureSchemeError,
)
from modelguard.hashing.digest import ArtifactDigest, hash_artifact
from modelguard.mbom.models import MLBOM
from modelguard.signing.envelope import (
    SCHEMA_VERSION_BOUND,
    SCHEMA_VERSION_LEGACY,
    SIGNATURE_TYPE_ED25519_LOCAL,
    SignatureEnvelope,
)
from modelguard.signing.schemes import (
    ALGORITHM_ED25519,
    DEFAULT_VERIFIERS,
    MAX_KEY_BYTES,
    MAX_SIGNATURE_BYTES,
    SignatureVerifier,
    decode_hex_strict,
    key_fingerprint,
)


@dataclass(frozen=True, slots=True)
class TamperCheckResult:
    """Result of re-hashing an artifact and comparing to a signed digest."""

    current_digest: str
    signed_digest: str
    matches: bool


@dataclass(frozen=True, slots=True)
class SignatureCheck:
    """What a successful signature verification established.

    ``key_fingerprint`` is computed from the public key bytes that
    actually verified the signature -- not read from any claimed field.
    ``key_bound`` says whether the signed payload itself committed to
    that key (format version 2). A valid signature still says nothing
    about whether the key is *trusted*; that is a separate check against
    a trust configuration.
    """

    algorithm: str
    key_fingerprint: str
    format_version: str
    key_bound: bool


def verify_envelope_signature(
    envelope: SignatureEnvelope,
    verifiers: Mapping[str, SignatureVerifier] = DEFAULT_VERIFIERS,
    *,
    allow_legacy_v1: bool = True,
) -> SignatureCheck:
    """Verify the signature over the payload, failing closed on anything odd.

    Order matters and is deliberate: the scheme is fixed by *signed*
    data (version 2) or by the one legacy value (version 1) **before**
    any key or signature byte is interpreted, and the unsigned
    ``signature_type`` can only agree with that, never override it.

    Raises ``UnsupportedSignatureSchemeError`` for an unknown format
    version, unknown algorithm, or a legacy signature when
    ``allow_legacy_v1`` is False; raises ``SignatureInvalidError`` for
    any inconsistency or cryptographic failure.

    This does NOT check that the key is trusted.
    """
    payload = envelope.payload
    version = payload.schema_version

    if version == SCHEMA_VERSION_LEGACY:
        if not allow_legacy_v1:
            raise UnsupportedSignatureSchemeError(
                "This is a legacy (format version 1) signature, which this verifier is "
                "configured to refuse because it does not commit to the signing key. "
                "Re-sign the artifact with ModelGuard 0.7.0 or later."
            )
        if payload.signature_algorithm is not None or payload.key_id is not None:
            raise SignatureInvalidError(
                "A format version 1 payload must not carry signature_algorithm or key_id."
            )
        if envelope.signature_type != SIGNATURE_TYPE_ED25519_LOCAL:
            raise UnsupportedSignatureSchemeError(
                f"Unsupported legacy signature_type {envelope.signature_type!r}; "
                f"only {SIGNATURE_TYPE_ED25519_LOCAL!r} exists for format version 1."
            )
        algorithm = ALGORITHM_ED25519
        claimed_key_id: str | None = None
    elif version == SCHEMA_VERSION_BOUND:
        if payload.signature_algorithm is None or payload.key_id is None:
            raise SignatureInvalidError(
                "A format version 2 payload must carry both signature_algorithm and key_id."
            )
        if envelope.signature_type != payload.signature_algorithm:
            raise SignatureInvalidError(
                f"The envelope labels the signature {envelope.signature_type!r} but the signed "
                f"payload says {payload.signature_algorithm!r}. The unsigned label was altered "
                "or the envelope was assembled incorrectly."
            )
        algorithm = payload.signature_algorithm
        claimed_key_id = payload.key_id
    else:
        raise UnsupportedSignatureSchemeError(
            f"Unsupported signature format version {version!r}; this verifier understands "
            f"{SCHEMA_VERSION_LEGACY!r} and {SCHEMA_VERSION_BOUND!r}."
        )

    verifier = verifiers.get(algorithm)
    if verifier is None:
        raise UnsupportedSignatureSchemeError(
            f"Signature algorithm {algorithm!r} is not supported by this verifier "
            f"(supported: {', '.join(sorted(verifiers))})."
        )

    public_key = decode_hex_strict(envelope.public_key, what="public_key", max_bytes=MAX_KEY_BYTES)
    signature = decode_hex_strict(envelope.signature, what="signature", max_bytes=MAX_SIGNATURE_BYTES)
    fingerprint = key_fingerprint(public_key)

    if claimed_key_id is not None and claimed_key_id != fingerprint:
        raise SignatureInvalidError(
            f"The signed payload commits to key_id {claimed_key_id!r} but the envelope carries "
            f"a public key with fingerprint {fingerprint!r}. The key was substituted."
        )

    verifier.verify(public_key, signature, payload.canonical_json())

    return SignatureCheck(
        algorithm=algorithm,
        key_fingerprint=fingerprint,
        format_version=version,
        key_bound=claimed_key_id is not None,
    )


def check_signature_bytes(
    envelope: SignatureEnvelope,
    verifiers: Mapping[str, SignatureVerifier] = DEFAULT_VERIFIERS,
    *,
    allow_legacy_v1: bool = True,
) -> None:
    """Verify the cryptographic signature over the payload.

    Raises ``SignatureInvalidError`` (or its subclass
    ``UnsupportedSignatureSchemeError``) on any failure. This function
    does NOT check whether the signing key is trusted -- that is a
    separate decision made against a trust configuration. Use
    ``verify_envelope_signature`` when you need the algorithm and key
    fingerprint that verified.
    """
    verify_envelope_signature(envelope, verifiers, allow_legacy_v1=allow_legacy_v1)


def check_artifact_digest(
    artifact_path: Path,
    envelope: SignatureEnvelope,
    hasher: Callable[[Path], ArtifactDigest] = hash_artifact,
) -> TamperCheckResult:
    """Hash the artifact on disk and compare it to the signed digest.

    ``hasher`` exists so a caller can substitute a caching hasher (see
    ``modelguard.cache``). Only the *digest computation* is pluggable;
    the comparison against the signed digest below is not, and always
    runs.
    """
    current = hasher(artifact_path)
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
