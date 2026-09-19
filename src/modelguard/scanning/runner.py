"""Scanner orchestration.

``run_scanners`` isolates each scanner in its own try/except: a
scanner that raises is recorded with status ``"error"`` and its
exception message, and does not stop the other scanners from running
or propagate out of this function. This is deliberate -- read the
project's "no silent fallback from secure behavior to insecure
behavior" rule together with "no fake completeness": a crashing
scanner must be visible (``status="error"``), never silently folded
into "this scanner found nothing".
"""

from __future__ import annotations

from pathlib import Path

from modelguard.hashing.digest import hash_artifact
from modelguard.manifest.models import Manifest
from modelguard.mbom.models import MLBOM
from modelguard.scanning.metadata import MetadataCompletenessScanner
from modelguard.scanning.models import Finding, ScanReport
from modelguard.scanning.protocol import Scanner
from modelguard.scanning.secrets import SecretScanner
from modelguard.scanning.unsafe_serialization import UnsafeSerializationScanner

DEFAULT_SCANNERS: tuple[Scanner, ...] = (
    UnsafeSerializationScanner(),
    SecretScanner(),
    MetadataCompletenessScanner(),
)


def run_scanners(
    artifact_path: Path,
    manifest: Manifest | None = None,
    mbom: MLBOM | None = None,
    scanners: tuple[Scanner, ...] | None = None,
) -> ScanReport:
    """Run every scanner in ``scanners`` (default: ``DEFAULT_SCANNERS``)
    against ``artifact_path`` and aggregate the results into one
    ``ScanReport``.

    Re-hashes the artifact to bind the report to a specific digest
    (rather than trusting a caller-supplied digest) so a stale report
    can never be silently attributed to a different artifact.
    """
    active = scanners if scanners is not None else DEFAULT_SCANNERS

    digest = hash_artifact(artifact_path)
    artifact_digest = f"{digest.algorithm}:{digest.digest}"

    statuses: dict[str, str] = {}
    errors: dict[str, str] = {}
    findings: list[Finding] = []

    for scanner in active:
        try:
            findings.extend(scanner.scan(artifact_path, manifest, mbom))
        except Exception as exc:  # noqa: BLE001 -- a scanner must never crash the whole run
            statuses[scanner.name] = "error"
            errors[scanner.name] = str(exc)
            continue
        statuses[scanner.name] = "ok"

    return ScanReport(
        artifact_digest=artifact_digest,
        scanner_statuses=statuses,
        scanner_errors=errors,
        findings=tuple(findings),
    )
