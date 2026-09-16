"""Generate an ML-BOM from a Manifest plus optional declared provenance."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from modelguard.manifest.models import Manifest
from modelguard.mbom.models import (
    MLBOM,
    EvidencedField,
    EvidenceLevel,
    MLBOMComponent,
    MLBOMMetadata,
    MLBOMProperties,
)


class DeclaredProvenance:
    """Optional, caller-supplied provenance claims for ML-BOM generation.

    All values passed here are recorded with ``EvidenceLevel.DECLARED``
    unless the caller explicitly overrides ``evidence`` per field. The
    generator never upgrades a DECLARED claim to VERIFIED on its own;
    only the verification pipeline (Phase 1's signature check, or a
    later scanner/policy stage) may do that.
    """

    def __init__(
        self,
        *,
        parent_models: list[str] | None = None,
        dataset_references: list[str] | None = None,
        training_code_commit: str | None = None,
        framework: str | None = None,
        license: str | None = None,
    ) -> None:
        self.parent_models = parent_models or []
        self.dataset_references = dataset_references or []
        self.training_code_commit = training_code_commit
        self.framework = framework
        self.license = license


def generate_mbom(manifest: Manifest, provenance: DeclaredProvenance | None = None) -> MLBOM:
    """Build an ML-BOM document bound to ``manifest``'s artifact digest.

    Binding is by value: the ML-BOM embeds ``manifest.digest`` directly,
    so any consumer can confirm the ML-BOM describes the exact artifact
    they have in hand, not merely an artifact with the same name.
    """
    prov = provenance or DeclaredProvenance()

    properties = MLBOMProperties(
        artifact_digest=f"{manifest.algorithm}:{manifest.digest}",
        artifact_type=manifest.artifact_type,
        parent_models=tuple(
            EvidencedField(value=p, evidence=EvidenceLevel.DECLARED) for p in prov.parent_models
        ),
        dataset_references=tuple(
            EvidencedField(value=d, evidence=EvidenceLevel.DECLARED)
            for d in prov.dataset_references
        ),
        training_code_commit=(
            EvidencedField(value=prov.training_code_commit, evidence=EvidenceLevel.DECLARED)
            if prov.training_code_commit
            else None
        ),
        framework=(
            EvidencedField(
                value=prov.framework or manifest.framework or "",
                evidence=EvidenceLevel.DECLARED,
            )
            if (prov.framework or manifest.framework)
            else None
        ),
        license=(
            EvidencedField(
                value=prov.license or manifest.license or "",
                evidence=EvidenceLevel.DECLARED,
            )
            if (prov.license or manifest.license)
            else None
        ),
        trust_status="unknown",
    )

    return MLBOM(
        serial_number=f"urn:uuid:{uuid.uuid4()}",
        metadata=MLBOMMetadata(timestamp=datetime.now(UTC).isoformat()),
        components=(
            MLBOMComponent(name=manifest.artifact_name or "unnamed-model", version=manifest.version),
        ),
        modelguard=properties,
    )
