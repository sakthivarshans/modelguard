from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from modelguard.cli.main import cli


def _clean_model(tmp_path: Path) -> Path:
    model_dir = tmp_path / "model"
    model_dir.mkdir()
    (model_dir / "config.json").write_text('{"hidden_size": 128}')
    (model_dir / "weights.safetensors").write_bytes(b"\x00\x01\x02\x03" * 16)
    return model_dir


def _risky_model(tmp_path: Path) -> Path:
    model_dir = tmp_path / "model"
    model_dir.mkdir()
    (model_dir / "weights.pkl").write_bytes(b"anything")
    (model_dir / "secret.txt").write_text("AKIAABCDEFGHIJKLMNOP")
    return model_dir


def test_scan_clean_model_exits_zero(tmp_path: Path) -> None:
    runner = CliRunner()
    model_dir = _clean_model(tmp_path)

    result = runner.invoke(cli, ["scan", str(model_dir)])

    assert result.exit_code == 0, result.output
    assert "Findings       : none" in result.output


def test_scan_risky_model_exits_nonzero_by_default(tmp_path: Path) -> None:
    runner = CliRunner()
    model_dir = _risky_model(tmp_path)

    result = runner.invoke(cli, ["scan", str(model_dir)])

    assert result.exit_code == 2, result.output
    assert "CRITICAL" in result.output
    assert "HIGH" in result.output


def test_scan_fail_on_critical_ignores_high_findings(tmp_path: Path) -> None:
    runner = CliRunner()
    model_dir = tmp_path / "model"
    model_dir.mkdir()
    (model_dir / "weights.pkl").write_bytes(b"anything")  # HIGH only, no secret

    result = runner.invoke(cli, ["scan", str(model_dir), "--fail-on", "critical"])

    assert result.exit_code == 0, result.output


def test_scan_fail_on_critical_still_catches_critical_findings(tmp_path: Path) -> None:
    runner = CliRunner()
    model_dir = _risky_model(tmp_path)

    result = runner.invoke(cli, ["scan", str(model_dir), "--fail-on", "critical"])

    assert result.exit_code == 2, result.output


def test_scan_json_output_is_well_formed(tmp_path: Path) -> None:
    runner = CliRunner()
    model_dir = _risky_model(tmp_path)

    result = runner.invoke(cli, ["scan", str(model_dir), "--format", "json"])

    payload = json.loads(result.output)
    assert payload["clean"] is False
    assert payload["scanner_statuses"]["unsafe_serialization"] == "ok"
    assert len(payload["findings"]) == 2
    # Secrets are never echoed back into the finding's evidence text.
    for finding in payload["findings"]:
        assert "AKIA" not in json.dumps(finding)


def test_scan_with_manifest_and_mbom_runs_metadata_scanner(tmp_path: Path) -> None:
    runner = CliRunner()
    model_dir = _clean_model(tmp_path)
    manifest_path = tmp_path / "model.manifest.json"
    bom_path = tmp_path / "model.bom.json"

    runner.invoke(cli, ["manifest", str(model_dir), "-o", str(manifest_path)])
    runner.invoke(cli, ["mbom", "generate", str(manifest_path), "-o", str(bom_path)])

    result = runner.invoke(
        cli,
        [
            "scan",
            str(model_dir),
            "--manifest",
            str(manifest_path),
            "--mbom",
            str(bom_path),
            "--format",
            "json",
        ],
    )

    payload = json.loads(result.output)
    categories = {f["category"] for f in payload["findings"]}
    assert "missing_metadata" in categories
    # Missing metadata is informational only -- must not push exit code
    # above 0 at the default --fail-on high threshold.
    assert result.exit_code == 0, result.output


def test_scan_nonexistent_path_exits_with_usage_error(tmp_path: Path) -> None:
    runner = CliRunner()

    result = runner.invoke(cli, ["scan", str(tmp_path / "does-not-exist")])

    assert result.exit_code != 0
