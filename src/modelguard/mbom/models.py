"""ML-BOM (AI/ML Bill of Materials) data model.

Phase 1 ships a minimal, CycloneDX-*inspired* document: it uses
CycloneDX's top-level envelope shape (bomFormat/specVersion/serialNumber/
metadata/components) so that a downstream CycloneDX consumer recognizes
the document shape, plus a ``modelguard`` extension block for
model-specific fields CycloneDX 1.6 does not yet standardize.

This is intentionally NOT a claim of full CycloneDX ML-BOM conformance.
Full conformance requires mapping every ModelGuard field to the formal
CycloneDX JSON schema and is tracked as future work (see Known
Limitations in the Phase 1 write-up).

Every provenance-relevant field carries an ``EvidenceLevel`` so a
consumer of the ML-BOM can tell a self-reported claim from a
cryptographically verified one.
"""

from __future__ import annotations

import json
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

MBOM_SCHEMA_VERSION = "1"
CYCLONEDX_SPEC_VERSION = "1.6"
# Not imported from modelguard.__version__ to avoid a circular import
# (modelguard/__init__.py -> sdk -> mbom). Kept in sync manually; a
# packaging-metadata lookup (importlib.metadata) is a cleaner fix for
# a later phase.
_TOOL_VERSION = "0.2.0"


class EvidenceLevel(str, Enum):
    """How strongly a claim in the ML-BOM is backed by evidence.

    DECLARED             -- stated by the artifact's publisher, unverified.
    SIGNED                -- stated in a payload covered by a valid signature.
    VERIFIED              -- independently recomputed and matched by ModelGuard
                              (e.g. the artifact digest itself).
    INDEPENDENTLY_TESTED  -- backed by a scanner or evaluation run.
    HUMAN_APPROVED        -- explicitly approved by an authorized reviewer.
    """

    DECLARED = "DECLARED"
    SIGNED = "SIGNED"
    VERIFIED = "VERIFIED"
    INDEPENDENTLY_TESTED = "INDEPENDENTLY_TESTED"
    HUMAN_APPROVED = "HUMAN_APPROVED"


class EvidencedField(BaseModel):
    """A single metadata value paired with its evidence level."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    value: str
    evidence: EvidenceLevel = EvidenceLevel.DECLARED


class MLBOMProperties(BaseModel):
    """The ``modelguard`` extension block.

    Fields with no known value are omitted rather than filled with
    placeholders, per the "no fake completeness" principle: an absent
    field means "not provided", not "empty string" or "unknown".
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    artifact_digest: str
    artifact_type: str
    parent_models: tuple[EvidencedField, ...] = Field(default_factory=tuple)
    dataset_references: tuple[EvidencedField, ...] = Field(default_factory=tuple)
    training_code_commit: EvidencedField | None = None
    framework: EvidencedField | None = None
    license: EvidencedField | None = None
    trust_status: str = "unknown"


class MLBOMMetadata(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    timestamp: str
    tool_name: str = "modelguard"
    tool_version: str = _TOOL_VERSION


class MLBOMComponent(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    type: str = "machine-learning-model"
    name: str
    version: str | None = None


class MLBOM(BaseModel):
    """Top-level ML-BOM document."""

    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)

    bom_format: str = Field(default="CycloneDX", alias="bomFormat")
    spec_version: str = Field(default=CYCLONEDX_SPEC_VERSION, alias="specVersion")
    schema_version: str = MBOM_SCHEMA_VERSION
    serial_number: str = Field(alias="serialNumber")
    version: int = 1
    metadata: MLBOMMetadata
    components: tuple[MLBOMComponent, ...]
    modelguard: MLBOMProperties

    def canonical_json(self) -> bytes:
        """Canonical bytes used for hashing and signing this ML-BOM."""
        data = self.model_dump(mode="json", by_alias=True, exclude_none=True)
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def to_json(self, *, indent: int | None = 2) -> str:
        """Human-readable JSON for writing to disk / display."""
        data = self.model_dump(mode="json", by_alias=True, exclude_none=True)
        return json.dumps(data, indent=indent, sort_keys=True)
