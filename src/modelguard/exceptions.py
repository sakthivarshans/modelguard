"""Exception hierarchy for ModelGuard.

Every error a caller can reasonably need to catch has its own type.
Callers should never need to parse a string message to know what went
wrong; the exception's type and attributes carry that information.
"""

from __future__ import annotations


class ModelGuardError(Exception):
    """Base class for all ModelGuard errors."""


# --------------------------------------------------------------------------
# Artifact and filesystem errors
# --------------------------------------------------------------------------


class ArtifactError(ModelGuardError):
    """Base class for artifact inspection and hashing errors."""


class ArtifactNotFoundError(ArtifactError):
    """The given artifact path does not exist."""

    def __init__(self, path: str) -> None:
        self.path = path
        super().__init__(f"Artifact path does not exist: {path}")


class UnsafePathError(ArtifactError):
    """A file inside an artifact directory would resolve outside the
    artifact root (path traversal) or is an unsafe symlink.

    ModelGuard fails closed here: it refuses to hash or read the file
    rather than silently skipping or silently following the link.
    """

    def __init__(self, path: str, reason: str) -> None:
        self.path = path
        self.reason = reason
        super().__init__(f"Unsafe path rejected: {path} ({reason})")


class EmptyArtifactError(ArtifactError):
    """An artifact directory contains no files that can be hashed."""

    def __init__(self, path: str) -> None:
        self.path = path
        super().__init__(f"Artifact contains no hashable files: {path}")


# --------------------------------------------------------------------------
# Manifest / ML-BOM errors
# --------------------------------------------------------------------------


class ManifestError(ModelGuardError):
    """Base class for manifest construction and validation errors."""


class ManifestValidationError(ManifestError):
    """A manifest failed schema validation."""


class MLBOMError(ModelGuardError):
    """Base class for ML-BOM generation and validation errors."""


class MLBOMValidationError(MLBOMError):
    """An ML-BOM document failed schema validation."""


# --------------------------------------------------------------------------
# Signing / verification errors
# --------------------------------------------------------------------------


class SigningError(ModelGuardError):
    """Base class for signing errors."""


class KeyError_(SigningError):
    """Base class for key-loading and key-format errors."""


class KeyNotFoundError(KeyError_):
    """The requested signing or verification key could not be located."""

    def __init__(self, path: str) -> None:
        self.path = path
        super().__init__(f"Key not found: {path}")


class InvalidKeyError(KeyError_):
    """A key file exists but is not a valid Ed25519 key of the expected type."""


class VerificationError(ModelGuardError):
    """Base class for verification failures.

    Raised by the low-level verifier when a signature or digest check
    fails outright (e.g. malformed signature bytes). Contrast with
    ``VerificationDenied``, which is raised by the high-level SDK when a
    verification *completed* but the result was not allowed.
    """


class SignatureInvalidError(VerificationError):
    """The cryptographic signature does not match the signed payload."""


class UnsupportedSignatureSchemeError(SignatureInvalidError):
    """The signature uses a scheme, algorithm, or format version this
    verifier does not implement or has been configured to refuse.

    A subclass of ``SignatureInvalidError`` on purpose: code that
    already denies on an invalid signature also denies on an unknown
    one. An unrecognized scheme is never treated as "probably fine".
    """


class MalformedSignatureError(VerificationError):
    """A signature file could not be parsed into a signature envelope
    (not JSON, wrong types, unknown fields, or over the size limit).

    Distinct from ``SignatureInvalidError``: nothing was verified
    because there was no well-formed envelope to verify.
    """


class SigningProviderError(SigningError):
    """A signing provider (local key, KMS, HSM, ...) failed, returned
    something unusable, or returned a signature that does not verify
    against its own public key. Signing fails closed: no envelope is
    produced.
    """


class DigestMismatchError(VerificationError):
    """The artifact's current digest does not match the signed digest.

    This is the primary tamper-detection signal: the artifact changed
    after it was signed.
    """

    def __init__(self, expected: str, actual: str) -> None:
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"Artifact digest mismatch: expected {expected}, got {actual}. "
            "The artifact may have been modified after signing."
        )


class VerificationDenied(ModelGuardError):
    """Raised by ``VerificationResult.raise_if_denied()`` when a completed
    verification was not allowed.
    """

    def __init__(self, reasons: list[str]) -> None:
        self.reasons = reasons
        joined = "; ".join(reasons) if reasons else "no reason provided"
        super().__init__(f"Verification denied: {joined}")


# --------------------------------------------------------------------------
# Trust configuration and deployment admission errors (Phase 5)
# --------------------------------------------------------------------------


class TrustConfigurationError(ModelGuardError):
    """The trust-root configuration is invalid (malformed or empty).

    Raised eagerly at configuration time. A malformed fingerprint that
    was silently accepted would simply never match anything, and an
    empty trust set would be indistinguishable from "trust roots not
    configured" -- both are configuration mistakes that must be loud.
    """


class AdmissionDenied(ModelGuardError):
    """Raised by ``AdmissionDecision.raise_if_blocked()`` when a
    deployment admission check did not admit the artifact.
    """

    def __init__(self, reasons: list[str]) -> None:
        self.reasons = reasons
        joined = "; ".join(reasons) if reasons else "no reason provided"
        super().__init__(f"Deployment admission denied: {joined}")
