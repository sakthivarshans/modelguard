from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from modelguard.cli.main import cli
from tests.conftest import SignedModel


def _verify_args(m: SignedModel, *extra: str) -> list[str]:
    return ["verify", str(m.artifact), "--mbom", str(m.mbom_path), "--signature", str(m.sig_path), *extra]


def _policy_args(m: SignedModel, *extra: str) -> list[str]:
    return [
        "policy", "check", str(m.artifact),
        "--mbom", str(m.mbom_path), "--signature", str(m.sig_path),
        "--policy", str(m.policy_path), *extra,
    ]  # fmt: skip


def test_keygen_prints_a_fingerprint_matching_the_fingerprint_command(tmp_path: Path) -> None:
    runner = CliRunner()
    out = runner.invoke(cli, ["keygen", "--identity", "a@b.c", "--output-dir", str(tmp_path)])
    printed = next(line.split(": ")[1] for line in out.output.splitlines() if line.startswith("Fingerprint"))
    fp = runner.invoke(cli, ["fingerprint", str(tmp_path / "a_at_b.c.modelguard.pub")])
    assert fp.exit_code == 0 and fp.output.strip() == printed and len(printed) == 64


def test_fingerprint_rejects_a_bad_key_file(tmp_path: Path) -> None:
    bad = tmp_path / "bad.pub"
    bad.write_bytes(b"short")
    assert CliRunner().invoke(cli, ["fingerprint", str(bad)]).exit_code == 1


def test_verify_with_trusted_fingerprint_is_allowed(signed_model: SignedModel) -> None:
    result = CliRunner().invoke(
        cli, _verify_args(signed_model, "--trusted-fingerprint", signed_model.fingerprint, "--format", "json")
    )
    payload = json.loads(result.output)
    assert result.exit_code == 0
    assert payload["signer_trusted"] is True and payload["digest_matches"] is True


def test_verify_without_fingerprint_says_signer_not_checked(signed_model: SignedModel) -> None:
    result = CliRunner().invoke(cli, _verify_args(signed_model))
    assert result.exit_code == 0
    assert "NOT CHECKED" in result.output


def test_verify_with_wrong_fingerprint_exits_2(signed_model: SignedModel) -> None:
    result = CliRunner().invoke(cli, _verify_args(signed_model, "--trusted-fingerprint", "e" * 64))
    assert result.exit_code == 2
    assert "NOT TRUSTED" in result.output


def test_verify_with_malformed_fingerprint_is_a_config_error_not_a_pass(signed_model: SignedModel) -> None:
    result = CliRunner().invoke(cli, _verify_args(signed_model, "--trusted-fingerprint", "nonsense"))
    assert result.exit_code == 1


def test_policy_check_allows_untampered_trusted_model(signed_model: SignedModel) -> None:
    result = CliRunner().invoke(
        cli, _policy_args(signed_model, "--trusted-fingerprint", signed_model.fingerprint)
    )
    assert result.exit_code == 0, result.output


def test_policy_check_denies_a_tampered_artifact_regression(signed_model: SignedModel) -> None:
    """The bug found in Phase 5: this used to exit 0."""
    (signed_model.artifact / "weights.bin").write_bytes(b"tampered")
    result = CliRunner().invoke(
        cli, _policy_args(signed_model, "--trusted-fingerprint", signed_model.fingerprint)
    )
    assert result.exit_code == 2
    assert "artifact_integrity" in result.output


def test_policy_requiring_trusted_signer_denies_when_no_fingerprint_given(signed_model: SignedModel) -> None:
    result = CliRunner().invoke(cli, _policy_args(signed_model))
    assert result.exit_code == 2
    assert "no trusted signer keys were configured" in result.output


def test_cache_dir_option_reports_cache_use(signed_model: SignedModel, tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from modelguard.cache import digest_cache as dc

    monkeypatch.setattr(dc, "RACY_MARGIN_NS", 0)
    cache = tmp_path / "cache"
    args = _verify_args(signed_model, "--cache-dir", str(cache), "--format", "json")
    runner = CliRunner()
    first = json.loads(runner.invoke(cli, args).output)
    second = json.loads(runner.invoke(cli, args).output)
    assert first["digest_from_cache"] is False
    assert second["digest_from_cache"] is True
