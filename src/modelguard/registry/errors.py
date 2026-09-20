"""Errors shared by every ``Registry`` backend."""

from __future__ import annotations

from modelguard.exceptions import ModelGuardError


class DuplicateRegistrationError(ModelGuardError):
    """A model_id + version pair was already registered.

    Registries are immutable-by-version: re-registering the same
    identifier with different contents would let a name silently
    point to a different artifact, which is exactly the "namespace
    confusion" threat the architecture document warns about. Register
    a new version instead.
    """

    def __init__(self, model_id: str, version: str) -> None:
        self.model_id = model_id
        self.version = version
        super().__init__(
            f"{model_id}@{version} is already registered. "
            "Register a new version instead of overwriting an existing one."
        )


class RegistryBackendError(ModelGuardError):
    """The registry backend could not complete an operation (outage,
    timeout, permission error, corrupt or unexpected schema).

    Callers must treat this as "unknown", never as "not revoked" or
    "not found": ``ModelGuard.verify`` lets it propagate, and
    ``admit()`` turns it into a denial. Messages never include
    connection strings or credentials.
    """


class RegistryConfigurationError(ModelGuardError):
    """The registry backend is misconfigured (e.g. an unsafe connection
    string). Raised eagerly at construction, before any connection."""
