"""Metadata-completeness scanner.

Purely informational: it never reports above LOW severity, and it
does not judge whether declared metadata is *true* -- only whether
fields useful for a reasonably complete provenance picture are
*present*. Truthfulness of a DECLARED field is explicitly out of
scope; see ``modelguard.mbom.models.EvidenceLevel``.

Returns no findings at all if neither a ``Manifest`` nor an ``MLBOM``
was supplied, since there is nothing to check -- an absent input is
not treated as "everything is missing".
"""

from __future__ import annotations

from pathlib import Path

from modelguard.manifest.models import Manifest
from modelguard.mbom.models import MLBOM
from modelguard.scanning.models import Confidence, Finding, Severity


class MetadataCompletenessScanner:
    """Flags missing license, lineage, and model-identity metadata."""

    name = "metadata_completeness"

    def scan(
        self, artifact_path: Path, manifest: Manifest | None, mbom: MLBOM | None
    ) -> list[Finding]:
        if manifest is None and mbom is None:
            return []

        findings: list[Finding] = []

        has_license = bool((manifest and manifest.license) or (mbom and mbom.modelguard.license))
        if not has_license:
            findings.append(
                Finding(
                    scanner=self.name,
                    category="missing_metadata",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    component="license",
                    message="No license is declared on the manifest or ML-BOM.",
                    remediation="Set a license identifier when building the manifest or ML-BOM.",
                )
            )

        has_lineage = bool(mbom and mbom.modelguard.parent_models)
        if not has_lineage:
            findings.append(
                Finding(
                    scanner=self.name,
                    category="missing_metadata",
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    component="parent_models",
                    message="The ML-BOM does not declare any parent model.",
                    remediation=(
                        "If this model was fine-tuned, merged, or quantized from another "
                        "model, record that lineage via DeclaredProvenance(parent_models=...)."
                    ),
                )
            )

        has_model_id = bool(manifest and manifest.model_id)
        has_version = bool(manifest and manifest.version)
        if not has_model_id or not has_version:
            missing = [
                n for n, present in (("model_id", has_model_id), ("version", has_version)) if not present
            ]
            findings.append(
                Finding(
                    scanner=self.name,
                    category="missing_metadata",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    component="/".join(missing),
                    message=f"The manifest is missing: {', '.join(missing)}.",
                    remediation="Set model_id and version via DeclaredMetadata before signing.",
                )
            )

        return findings
