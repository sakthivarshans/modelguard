"""Scanner finding and scan-report data models.

A ``Finding`` is one scanner's observation about one component of an
artifact -- e.g. "this file looks like a pickle-based format". A
``ScanReport`` aggregates every finding from every scanner that ran
against one artifact, plus a per-scanner run status, so a caller (and
the policy engine) can distinguish "this scanner ran and found
nothing" from "this scanner never ran or crashed".

Consistent with the project's "no fake completeness" principle: a
scanner that raises is recorded as ``"error"`` in ``scanner_statuses``,
never silently folded into "clean". See ``ScanReport.clean``.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum


class Severity(str, Enum):
    """Finding severity, ordered from least to most severe."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Confidence(str, Enum):
    """How confident the scanner is that a finding is a true positive."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass(frozen=True, slots=True)
class Finding:
    """One scanner's observation about one component of an artifact.

    ``evidence`` is a short, non-sensitive description of what was
    matched (e.g. a file extension or a pattern name) -- it must never
    contain the secret, key material, or file content itself. See the
    project's "never log secrets" rule.
    """

    scanner: str
    category: str
    severity: Severity
    confidence: Confidence
    component: str
    message: str
    remediation: str | None = None
    evidence: str | None = None
    status: str = "open"
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


@dataclass(frozen=True, slots=True)
class ScanReport:
    """The aggregated result of running one or more scanners against
    one artifact.
    """

    artifact_digest: str
    scanner_statuses: dict[str, str]  # scanner name -> "ok" | "error"
    scanner_errors: dict[str, str]  # scanner name -> error message, present only for "error"
    findings: tuple[Finding, ...] = field(default_factory=tuple)
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    scanned_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    @property
    def all_scanners_ok(self) -> bool:
        """Whether every scanner that ran finished without raising.

        ``True`` vacuously if no scanners ran at all -- callers that
        care about "did a scan actually happen" should check
        ``scanner_statuses`` directly, not rely on this alone.
        """
        return all(status == "ok" for status in self.scanner_statuses.values())

    @property
    def clean(self) -> bool:
        """Whether the artifact scanned clean: every scanner that ran
        finished successfully AND found nothing at all.

        Requiring ``all_scanners_ok`` here is deliberate: a scanner
        that errored out contributes zero findings by construction,
        but that means "unknown", not "clean" -- see the module
        docstring's "no fake completeness" note.
        """
        return self.all_scanners_ok and len(self.findings) == 0

    def count(self, severity: Severity) -> int:
        """How many findings were reported at exactly this severity."""
        return sum(1 for f in self.findings if f.severity == severity)
