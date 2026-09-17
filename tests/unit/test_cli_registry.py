from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from modelguard.cli.main import cli


def _sign_and_register(runner: CliRunner, tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    model_dir = tmp_path / "model"
    model_dir.mkdir()
    (model_dir / "weights.bin").write_bytes(b"weights")

    manifest_path = tmp_path / "model.manifest.json"
    bom_path = tmp_path / "model.bom.json"
    sig_path = tmp_path / "model.sig.json"
    storage_root = tmp_path / ".modelguard"
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
    result = runner.invoke(
        cli,
        [
            "register",
            str(manifest_path),
            str(bom_path),
            "--actor",
            "dev@example.com",
            "--storage-root",
            str(storage_root),
        ],
    )
    assert result.exit_code == 0, result.output

    return model_dir, bom_path, sig_path, storage_root


def test_cli_register_and_resolve(tmp_path: Path) -> None:
    runner = CliRunner()
    _, _, _, storage_root = _sign_and_register(runner, tmp_path)

    result = runner.invoke(
        cli, ["resolve", "demo", "1.0.0", "--storage-root", str(storage_root), "--format", "json"]
    )
    assert result.exit_code == 0, result.output
    assert '"revoked": false' in result.output


def test_cli_resolve_unregistered_model_errors(tmp_path: Path) -> None:
    runner = CliRunner()
    storage_root = tmp_path / ".modelguard"
    result = runner.invoke(cli, ["resolve", "nope", "1.0.0", "--storage-root", str(storage_root)])
    assert result.exit_code == 1


def test_cli_revoke_then_verify_is_denied(tmp_path: Path) -> None:
    runner = CliRunner()
    model_dir, bom_path, sig_path, storage_root = _sign_and_register(runner, tmp_path)

    result = runner.invoke(
        cli,
        [
            "verify",
            str(model_dir),
            "--mbom",
            str(bom_path),
            "--signature",
            str(sig_path),
            "--storage-root",
            str(storage_root),
        ],
    )
    assert result.exit_code == 0, result.output  # allowed before revocation

    result = runner.invoke(
        cli,
        [
            "revoke",
            "demo",
            "1.0.0",
            "--actor",
            "security@example.com",
            "--reason",
            "compromised",
            "--storage-root",
            str(storage_root),
        ],
    )
    assert result.exit_code == 0, result.output

    result = runner.invoke(
        cli,
        [
            "verify",
            str(model_dir),
            "--mbom",
            str(bom_path),
            "--signature",
            str(sig_path),
            "--storage-root",
            str(storage_root),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 2, result.output
    assert '"revoked": true' in result.output


def test_cli_provenance_record_and_lineage(tmp_path: Path) -> None:
    runner = CliRunner()
    storage_root = tmp_path / ".modelguard"

    result = runner.invoke(
        cli,
        [
            "provenance",
            "record",
            "fine-tuned",
            "FINE_TUNED_FROM",
            "base",
            "--actor",
            "dev@example.com",
            "--storage-root",
            str(storage_root),
        ],
    )
    assert result.exit_code == 0, result.output

    result = runner.invoke(
        cli, ["lineage", "fine-tuned", "--storage-root", str(storage_root)]
    )
    assert result.exit_code == 0
    assert "fine-tuned --FINE_TUNED_FROM--> base" in result.output


def test_cli_provenance_record_rejects_unknown_relationship(tmp_path: Path) -> None:
    runner = CliRunner()
    storage_root = tmp_path / ".modelguard"

    result = runner.invoke(
        cli,
        [
            "provenance",
            "record",
            "a",
            "NOT_A_REAL_RELATIONSHIP",
            "b",
            "--actor",
            "dev@example.com",
            "--storage-root",
            str(storage_root),
        ],
    )
    assert result.exit_code == 1


def test_cli_lineage_empty_for_unknown_model(tmp_path: Path) -> None:
    runner = CliRunner()
    storage_root = tmp_path / ".modelguard"

    result = runner.invoke(
        cli, ["lineage", "demo", "--storage-root", str(storage_root)]
    )
    assert result.exit_code == 0
    assert "No recorded lineage" in result.output
