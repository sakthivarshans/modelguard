"""Errors for artifact/blob storage."""

from __future__ import annotations

from modelguard.exceptions import ModelGuardError


class ArtifactStoreError(ModelGuardError):
    """A storage backend operation failed (outage, permission, quota, ...).

    Treat as "unknown", never as "absent". Messages contain a category
    and a provider error *code* only -- never endpoints, credentials, or
    provider-supplied free text.
    """


class ArtifactNotFoundError(ArtifactStoreError):
    """The requested blob does not exist."""


class ArtifactIntegrityError(ArtifactStoreError):
    """Stored or transferred bytes did not match the expected digest, or
    exceeded a size limit. Nothing from a failed transfer is left at the
    destination."""


class StoreConfigurationError(ModelGuardError):
    """The storage backend is misconfigured (unsafe endpoint, bad prefix,
    missing optional dependency). Raised eagerly at construction."""
