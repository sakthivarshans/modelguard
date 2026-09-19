"""Security tests for the scanning subsystem: no scanner may execute,
import, or deserialize artifact content, and symlink-based scan evasion
must be reported, never silently followed. See
docs/security/threat-model.md, "Phase 4 Addendum".
"""

from __future__ import annotations

import os
import pickle
from pathlib import Path

import pytest

from modelguard.scanning import Severity, run_scanners
from modelguard.scanning.secrets import SecretScanner
from modelguard.scanning.unsafe_serialization import UnsafeSerializationScanner


def test_run_scanners_never_unpickles_a_hostile_payload(tmp_path: Path) -> None:
    """A crafted pickle stream whose __reduce__ has a real side effect
    (writing a marker file) must never be triggered by a scan. If any
    scanner ever unpickled artifact content, this marker would exist
    after run_scanners() returns.
    """
    marker = tmp_path / "PWNED"

    class _Hostile:
        def __reduce__(self) -> tuple[object, tuple[str]]:
            return (os.system, (f"touch {marker}",))

    root = tmp_path / "model"
    root.mkdir()
    (root / "weights.pkl").write_bytes(pickle.dumps(_Hostile()))

    report = run_scanners(root)

    assert not marker.exists()
    assert report.all_scanners_ok
    assert any(f.category == "unsafe_deserialization" for f in report.findings)


def test_scanners_never_import_or_exec_artifact_content(tmp_path: Path) -> None:
    """A .py-like file with real side-effecting code at module scope
    must never actually run during a scan -- scanners only read bytes.
    """
    marker = tmp_path / "EXECUTED"
    root = tmp_path / "model"
    root.mkdir()
    (root / "custom_model.py").write_text(f"open(r'{marker}', 'w').close()\n")

    run_scanners(root)

    assert not marker.exists()


@pytest.mark.skipif(os.name == "nt", reason="symlinks require special privileges on Windows")
def test_symlink_outside_artifact_root_is_reported_not_followed(tmp_path: Path) -> None:
    """A symlink inside the artifact that points to a file outside the
    artifact root (e.g. a host secret, or another tenant's model) must
    never have its target's content scanned -- only a skip finding.
    """
    root = tmp_path / "model"
    root.mkdir()
    outside_secret = tmp_path / "host_secret.pem"
    outside_secret.write_text("-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n")
    (root / "innocuous.bin").symlink_to(outside_secret)

    findings = SecretScanner().scan(root, None, None)

    assert not any(f.category == "pem_private_key" for f in findings)
    skip_findings = [f for f in findings if f.category == "scan_skipped"]
    assert len(skip_findings) == 1
    assert skip_findings[0].severity == Severity.LOW


@pytest.mark.skipif(os.name == "nt", reason="symlinks require special privileges on Windows")
def test_symlinked_directory_is_not_descended_into(tmp_path: Path) -> None:
    root = tmp_path / "model"
    root.mkdir()
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    (outside_dir / "secret.pkl").write_bytes(b"data")
    (root / "linked_dir").symlink_to(outside_dir)

    findings = UnsafeSerializationScanner().scan(root, None, None)

    # The linked-to directory's contents must never be scanned or
    # reported as if they belonged to this artifact.
    assert not any("secret.pkl" in f.component for f in findings)


def test_a_buggy_or_compromised_scanner_cannot_silently_report_clean(tmp_path: Path) -> None:
    """If a scanner is buggy or compromised and raises instead of
    running, the ScanReport must make that visible -- a caller (or the
    policy engine's fail-closed count rules) must never mistake
    "the scanner crashed" for "the scanner found nothing".
    """

    class _BrokenScanner:
        name = "broken"

        def scan(self, artifact_path: object, manifest: object, mbom: object) -> list:  # type: ignore[type-arg]
            raise RuntimeError("compromised or buggy scanner")

    root = tmp_path / "model"
    root.mkdir()
    (root / "weights.bin").write_bytes(b"data")

    report = run_scanners(root, scanners=(_BrokenScanner(),))  # type: ignore[arg-type]

    assert report.scanner_statuses["broken"] == "error"
    assert not report.clean
    assert not report.all_scanners_ok
