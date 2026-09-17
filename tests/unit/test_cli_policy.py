from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from modelguard.cli.main import cli


def _sign_workflow(runner: CliRunner, tmp_path: Path) -> tuple[Path, Path, Path]:
    model_dir = tmp_path / "model"
    model_dir.mkdir()
    (model_dir / "weights.bin").write_bytes(b"weights")

    manifest_path = tmp_path / "m.json"
    bom_path = tmp_path / "b.json"
    sig_path = tmp_path / "s.json"
    key_dir = tmp_path / "keys"

    runner.invoke(
        cli,
        [
            "manifest",
            str(model_dir),
            "-o",
            str(manifest_path),
            "--model-id",
            "demo",
            "--version",
            "1.0.0",
            "--license",
            "Apache-2.0",
        ],
    )
    runner.invoke(cli, ["mbom", "generate", str(manifest_path), "-o", str(bom_path)])
    runner.invoke(cli, ["keygen", "--identity", "dev@example.com", "--output-dir", str(key_dir)])
    key_path = key_dir / "dev_at_example.com.modelguard.key"
    runner.invoke(
        cli,
        [
            "sign",
            str(model_dir),
            "--manifest",
            str(manifest_path),
            "--mbom",
            str(bom_path),
            "--key",
            str(key_path),
            "--identity",
            "dev@example.com",
            "-o",
            str(sig_path),
        ],
    )
    return model_dir, bom_path, sig_path


def _write_policy(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(text)
    return path


def test_policy_validate_valid_file(tmp_path: Path) -> None:
    runner = CliRunner()
    policy_path = _write_policy(
        tmp_path,
        "policy:\n  name: demo\nrules:\n  require_valid_signature:\n    enabled: true\n",
    )

    result = runner.invoke(cli, ["policy", "validate", str(policy_path)])

    assert result.exit_code == 0, result.output
    assert "demo" in result.output


def test_policy_validate_invalid_file(tmp_path: Path) -> None:
    runner = CliRunner()
    policy_path = _write_policy(tmp_path, "rules:\n  require_valid_signature:\n    enabled: true\n")

    result = runner.invoke(cli, ["policy", "validate", str(policy_path)])

    assert result.exit_code == 1


def test_policy_check_allows(tmp_path: Path) -> None:
    runner = CliRunner()
    model_dir, bom_path, sig_path = _sign_workflow(runner, tmp_path)
    policy_path = _write_policy(
        tmp_path,
        "policy:\n  name: strict\nrules:\n"
        "  require_valid_signature: {enabled: true, on_fail: deny}\n"
        "  require_license: {enabled: true, on_fail: deny}\n",
    )

    result = runner.invoke(
        cli,
        [
            "policy",
            "check",
            str(model_dir),
            "--mbom",
            str(bom_path),
            "--signature",
            str(sig_path),
            "--policy",
            str(policy_path),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0, result.output
    assert '"decision": "ALLOW"' in result.output


def test_policy_check_denies_and_returns_exit_code_2(tmp_path: Path) -> None:
    runner = CliRunner()
    model_dir, bom_path, sig_path = _sign_workflow(runner, tmp_path)
    policy_path = _write_policy(
        tmp_path,
        "policy:\n  name: strict\nrules:\n"
        "  require_known_lineage: {enabled: true, on_fail: deny}\n",
    )

    result = runner.invoke(
        cli,
        [
            "policy",
            "check",
            str(model_dir),
            "--mbom",
            str(bom_path),
            "--signature",
            str(sig_path),
            "--policy",
            str(policy_path),
        ],
    )

    assert result.exit_code == 2, result.output
    assert "DENY" in result.output


def test_policy_check_review_required_returns_exit_code_3(tmp_path: Path) -> None:
    runner = CliRunner()
    model_dir, bom_path, sig_path = _sign_workflow(runner, tmp_path)
    policy_path = _write_policy(
        tmp_path,
        "policy:\n  name: soft\nrules:\n"
        "  require_known_lineage: {enabled: true, on_fail: review}\n",
    )

    result = runner.invoke(
        cli,
        [
            "policy",
            "check",
            str(model_dir),
            "--mbom",
            str(bom_path),
            "--signature",
            str(sig_path),
            "--policy",
            str(policy_path),
        ],
    )

    assert result.exit_code == 3, result.output


def test_policy_check_with_revoked_model_returns_exit_code_5(tmp_path: Path) -> None:
    runner = CliRunner()
    model_dir, bom_path, sig_path = _sign_workflow(runner, tmp_path)
    storage_root = tmp_path / ".modelguard"

    runner.invoke(
        cli, ["register", str(tmp_path / "m.json"), str(bom_path), "--actor", "dev@example.com", "--storage-root", str(storage_root)]
    )
    runner.invoke(
        cli,
        [
            "revoke",
            "demo",
            "1.0.0",
            "--actor",
            "security@example.com",
            "--reason",
            "bad",
            "--storage-root",
            str(storage_root),
        ],
    )

    policy_path = _write_policy(
        tmp_path, "policy:\n  name: p\nrules:\n  reject_revoked_models: {enabled: true, on_fail: deny}\n"
    )

    result = runner.invoke(
        cli,
        [
            "policy",
            "check",
            str(model_dir),
            "--mbom",
            str(bom_path),
            "--signature",
            str(sig_path),
            "--policy",
            str(policy_path),
            "--storage-root",
            str(storage_root),
        ],
    )

    assert result.exit_code == 5, result.output
