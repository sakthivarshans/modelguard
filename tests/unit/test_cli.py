from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from modelguard.cli.main import cli


def _make_model(tmp_path: Path) -> Path:
    model_dir = tmp_path / "model"
    model_dir.mkdir()
    (model_dir / "config.json").write_text('{"hidden_size": 128}')
    (model_dir / "weights.safetensors").write_bytes(b"\x00\x01\x02\x03" * 16)
    return model_dir


def test_full_cli_workflow_allows_untampered_model(tmp_path: Path) -> None:
    runner = CliRunner()
    model_dir = _make_model(tmp_path)
    manifest_path = tmp_path / "model.manifest.json"
    bom_path = tmp_path / "model.bom.json"
    key_dir = tmp_path / "keys"
    sig_path = tmp_path / "model.sig.json"

    result = runner.invoke(cli, ["inspect", str(model_dir)])
    assert result.exit_code == 0, result.output

    result = runner.invoke(
        cli,
        ["manifest", str(model_dir), "-o", str(manifest_path), "--model-id", "demo-classifier"],
    )
    assert result.exit_code == 0, result.output
    assert manifest_path.exists()

    result = runner.invoke(
        cli, ["mbom", "generate", str(manifest_path), "-o", str(bom_path)]
    )
    assert result.exit_code == 0, result.output
    assert bom_path.exists()

    result = runner.invoke(
        cli, ["keygen", "--identity", "dev@example.com", "--output-dir", str(key_dir)]
    )
    assert result.exit_code == 0, result.output
    key_path = key_dir / "dev_at_example.com.modelguard.key"
    assert key_path.exists()

    result = runner.invoke(
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
    assert result.exit_code == 0, result.output
    assert sig_path.exists()

    result = runner.invoke(
        cli,
        [
            "verify",
            str(model_dir),
            "--mbom",
            str(bom_path),
            "--signature",
            str(sig_path),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0, result.output
    assert '"allowed": true' in result.output


def test_cli_verify_returns_exit_code_2_when_denied(tmp_path: Path) -> None:
    runner = CliRunner()
    model_dir = _make_model(tmp_path)
    manifest_path = tmp_path / "model.manifest.json"
    bom_path = tmp_path / "model.bom.json"
    key_dir = tmp_path / "keys"
    sig_path = tmp_path / "model.sig.json"

    runner.invoke(cli, ["manifest", str(model_dir), "-o", str(manifest_path)])
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

    # Tamper with the artifact after signing.
    (model_dir / "weights.safetensors").write_bytes(b"tampered bytes")

    result = runner.invoke(
        cli, ["verify", str(model_dir), "--mbom", str(bom_path), "--signature", str(sig_path)]
    )

    assert result.exit_code == 2
    assert "DENIED" in result.output


def test_cli_sign_refuses_stale_manifest(tmp_path: Path) -> None:
    """If the artifact changes after `manifest` but before `sign`, signing
    must fail rather than sign a manifest that no longer matches reality.
    """
    runner = CliRunner()
    model_dir = _make_model(tmp_path)
    manifest_path = tmp_path / "model.manifest.json"
    bom_path = tmp_path / "model.bom.json"
    key_dir = tmp_path / "keys"
    sig_path = tmp_path / "model.sig.json"

    runner.invoke(cli, ["manifest", str(model_dir), "-o", str(manifest_path)])
    runner.invoke(cli, ["mbom", "generate", str(manifest_path), "-o", str(bom_path)])
    runner.invoke(cli, ["keygen", "--identity", "dev@example.com", "--output-dir", str(key_dir)])
    key_path = key_dir / "dev_at_example.com.modelguard.key"

    # Mutate the artifact between manifest generation and signing.
    (model_dir / "weights.safetensors").write_bytes(b"different bytes now")

    result = runner.invoke(
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

    assert result.exit_code == 1
    assert not sig_path.exists()
