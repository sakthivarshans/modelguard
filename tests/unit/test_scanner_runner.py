from __future__ import annotations

from pathlib import Path

from modelguard.manifest.models import Manifest
from modelguard.mbom.models import MLBOM
from modelguard.scanning import Confidence, Finding, Severity, run_scanners
from modelguard.scanning.runner import DEFAULT_SCANNERS


class _RaisingScanner:
    name = "raising_scanner"

    def scan(
        self, artifact_path: Path, manifest: Manifest | None, mbom: MLBOM | None
    ) -> list[Finding]:
        raise RuntimeError("boom")


class _StubScanner:
    name = "stub_scanner"

    def scan(
        self, artifact_path: Path, manifest: Manifest | None, mbom: MLBOM | None
    ) -> list[Finding]:
        return [
            Finding(
                scanner=self.name,
                category="stub",
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                component="stub",
                message="stub finding",
            )
        ]


def test_default_scanners_all_run_and_report_ok(tmp_path: Path) -> None:
    root = tmp_path / "model"
    root.mkdir()
    (root / "model.safetensors").write_bytes(b"weights")

    report = run_scanners(root)

    assert set(report.scanner_statuses) == {s.name for s in DEFAULT_SCANNERS}
    assert report.all_scanners_ok
    assert report.scanner_errors == {}


def test_report_is_bound_to_the_artifact_digest(tmp_path: Path) -> None:
    from modelguard.hashing.digest import hash_artifact

    root = tmp_path / "model"
    root.mkdir()
    (root / "model.safetensors").write_bytes(b"weights")

    expected = hash_artifact(root)
    report = run_scanners(root)

    assert report.artifact_digest == f"{expected.algorithm}:{expected.digest}"


def test_findings_from_multiple_scanners_are_aggregated(tmp_path: Path) -> None:
    root = tmp_path / "model"
    root.mkdir()
    (root / "weights.pkl").write_bytes(b"x")
    (root / "secret.txt").write_text("AKIAABCDEFGHIJKLMNOP")

    report = run_scanners(root)

    scanners_that_found_something = {f.scanner for f in report.findings}
    assert "unsafe_serialization" in scanners_that_found_something
    assert "secrets" in scanners_that_found_something


def test_a_raising_scanner_is_isolated_and_does_not_abort_the_run(tmp_path: Path) -> None:
    root = tmp_path / "model"
    root.mkdir()
    (root / "weights.bin").write_bytes(b"data")

    report = run_scanners(root, scanners=(_RaisingScanner(), _StubScanner()))

    assert report.scanner_statuses["raising_scanner"] == "error"
    assert "boom" in report.scanner_errors["raising_scanner"]
    assert report.scanner_statuses["stub_scanner"] == "ok"
    assert any(f.scanner == "stub_scanner" for f in report.findings)
    assert not report.all_scanners_ok


def test_clean_requires_both_zero_findings_and_all_scanners_ok(tmp_path: Path) -> None:
    root = tmp_path / "model"
    root.mkdir()
    (root / "weights.bin").write_bytes(b"data")

    # All scanners ok, zero findings -> clean.
    clean_report = run_scanners(root, scanners=())
    assert clean_report.clean

    # A scanner errors and produces zero findings -- must NOT be
    # reported as clean; an errored scanner contributing no findings
    # is "unknown", not "nothing wrong".
    dirty_report = run_scanners(root, scanners=(_RaisingScanner(),))
    assert dirty_report.findings == ()
    assert not dirty_report.clean


def test_count_helper_counts_by_severity(tmp_path: Path) -> None:
    root = tmp_path / "model"
    root.mkdir()
    (root / "weights.pkl").write_bytes(b"x")
    (root / "secret.txt").write_text("AKIAABCDEFGHIJKLMNOP")

    report = run_scanners(root)

    assert report.count(Severity.CRITICAL) == 1  # the AWS key
    assert report.count(Severity.HIGH) == 1  # the .pkl extension
