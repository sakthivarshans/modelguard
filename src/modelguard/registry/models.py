"""Registry data model.

A ``RegistryRecord`` is what the registry stores for one registered
model version: its manifest, its ML-BOM, its signature (if any), and
registration metadata. ``model_id`` + ``version`` is the registry's
human-facing key; ``artifact_digest`` is the immutable identity used
for digest-based resolution, matching the architecture document's
"names are mutable, digests are not" principle.
"""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field

from modelguard.manifest.models import Manifest
from modelguard.mbom.models import MLBOM


class RevocationRecord(BaseModel):
    """A revocation decision for a specific model version."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    model_id: str
    version: str
    revoked_by: str
    reason: str
    revoked_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class RegistryRecord(BaseModel):
    """A single registered model version."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    model_id: str
    version: str
    artifact_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")  # copied from manifest
    manifest: Manifest
    mbom: MLBOM
    registered_by: str
    registered_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())

    @property
    def uri(self) -> str:
        """The immutable model URI: ``model://<model_id>@sha256:<digest>``."""
        return f"model://{self.model_id}@{self.artifact_digest}"
