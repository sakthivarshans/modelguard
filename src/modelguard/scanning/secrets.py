"""Narrow, high-confidence secret scanner.

Deliberately NOT a general-purpose secret scanner: it matches a small
set of patterns with a distinctive, low-false-positive structure (AWS
access key IDs, PEM private key headers, GitHub personal access
tokens, Slack tokens) rather than trying to catch every possible
credential shape. A broader scanner needs entropy analysis and a much
larger false-positive budget; that is future work, not this scanner's
job -- see ``docs/limitations.md``.

Consistent with the "never log secrets" rule: a matched finding's
``evidence`` records only the pattern name, never the matched text.
"""

from __future__ import annotations

import re
from pathlib import Path
from re import Pattern

from modelguard.manifest.models import Manifest
from modelguard.mbom.models import MLBOM
from modelguard.scanning._walk import ScannableFile, iter_scannable_files
from modelguard.scanning.models import Confidence, Finding, Severity

_MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MiB -- secret patterns are short; larger files are skipped.
_BINARY_SNIFF_SIZE = 1024

_PATTERNS: tuple[tuple[str, Pattern[str], Severity], ...] = (
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), Severity.CRITICAL),
    (
        "pem_private_key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"),
        Severity.CRITICAL,
    ),
    ("github_pat", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b"), Severity.HIGH),
    ("slack_token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,72}\b"), Severity.HIGH),
)


def _looks_binary(prefix: bytes) -> bool:
    return b"\x00" in prefix


class SecretScanner:
    """Matches a narrow set of high-confidence secret patterns in text files."""

    name = "secrets"

    def scan(
        self, artifact_path: Path, manifest: Manifest | None, mbom: MLBOM | None
    ) -> list[Finding]:
        findings: list[Finding] = []
        for item in iter_scannable_files(artifact_path, self.name):
            if isinstance(item, Finding):
                findings.append(item)
                continue
            findings.extend(self._scan_file(item))
        return findings

    def _scan_file(self, file: ScannableFile) -> list[Finding]:
        try:
            size = file.absolute_path.stat().st_size
        except OSError:
            return []
        if size > _MAX_FILE_SIZE:
            return []

        try:
            raw = file.absolute_path.read_bytes()
        except OSError:
            return []

        if _looks_binary(raw[:_BINARY_SNIFF_SIZE]):
            return []

        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return []

        findings: list[Finding] = []
        for category, pattern, severity in _PATTERNS:
            if pattern.search(text) is None:
                continue
            findings.append(
                Finding(
                    scanner=self.name,
                    category=category,
                    severity=severity,
                    confidence=Confidence.HIGH,
                    component=file.relative_path,
                    message=f"Content matching a {category.replace('_', ' ')} pattern was found.",
                    remediation=(
                        "Remove this credential from the artifact and rotate it -- treat it "
                        "as compromised from the moment it was committed or packaged."
                    ),
                    evidence=f"pattern={category}",
                )
            )
        return findings
