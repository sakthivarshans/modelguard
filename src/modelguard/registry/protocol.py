"""Registry interface.

Defined as a ``Protocol`` so a future PostgreSQL/S3-backed registry can
implement the same shape without ``LocalRegistry`` or callers needing
to change. Per the architecture rules, the domain layer (SDK, CLI)
should depend on this interface, not on ``LocalRegistry`` directly.
"""

from __future__ import annotations

from typing import Protocol

from modelguard.registry.models import RegistryRecord, RevocationRecord


class Registry(Protocol):
    def register(self, record: RegistryRecord) -> RegistryRecord: ...

    def get(self, model_id: str, version: str) -> RegistryRecord | None: ...

    def get_by_digest(self, artifact_digest: str) -> RegistryRecord | None: ...

    def list_versions(self, model_id: str) -> list[str]: ...

    def revoke(self, record: RevocationRecord) -> RevocationRecord: ...

    def unrevoke(self, model_id: str, version: str, actor: str, reason: str) -> None: ...

    def is_revoked(self, model_id: str, version: str) -> RevocationRecord | None: ...
