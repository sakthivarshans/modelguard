"""CLI coverage: `modelguard trust validate` and `--trust-config`."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from modelguard.cli.main import cli
from tests.conftest import SignedModel


def _write(path: Path, text: str) -> Path:
    path.write_text(text)
    return path


def test_trust_validate_reports_key_count_and_statuses(tmp_path: Path) -> None:
    fp = "a" * 64
    path = _write(
        tmp_path / "trust.yaml",
        f"keys:\n  - key_id: '{fp}'\n    label: prod\n  - key_id: '{'b' * 64}'\n    status: retired\n",
    )
    out = CliRunner().invoke(cli, ["trust", "validate", str(path)])
    assert out.exit_code == 0
    assert "Keys: 2" in out.output
    assert "active: 1" in out.output
    assert "retired: 1" in out.output
    assert "(prod)" in out.output


def test_trust_validate_json_output(tmp_path: Path) -> None:
    fp = "a" * 64
    path = _write(tmp_path / "trust.yaml", f"keys:\n  - key_id: '{fp}'\n")
    out = CliRunner().invoke(cli, ["trust", "validate", str(path), "--format", "json"])
    payload = json.loads(out.output)
    assert payload["key_count"] == 1
    assert payload["keys"][0]["key_id"] == fp


def test_trust_validate_rejects_malformed_file(tmp_path: Path) -> None:
    path = _write(tmp_path / "trust.yaml", "keys:\n  - key_id: not-valid\n")
    out = CliRunner().invoke(cli, ["trust", "validate", str(path)])
    assert out.exit_code == 1
    assert "Error:" in out.output


def test_verify_with_trust_config_allows(signed_model: SignedModel, tmp_path: Path) -> None:
    path = _write(tmp_path / "trust.yaml", f"keys:\n  - key_id: '{signed_model.fingerprint}'\n")
    out = CliRunner().invoke(
        cli,
        [
            "verify", str(signed_model.artifact),
            "--mbom", str(signed_model.mbom_path),
            "--signature", str(signed_model.sig_path),
            "--trust-config", str(path),
        ],
    )  # fmt: skip
    assert out.exit_code == 0
    assert "Signer       : trusted" in out.output


def test_verify_with_expired_trust_config_denies(signed_model: SignedModel, tmp_path: Path) -> None:
    path = _write(
        tmp_path / "trust.yaml",
        f"keys:\n  - key_id: '{signed_model.fingerprint}'\n    not_after: '2000-01-01T00:00:00Z'\n",
    )
    out = CliRunner().invoke(
        cli,
        [
            "verify", str(signed_model.artifact),
            "--mbom", str(signed_model.mbom_path),
            "--signature", str(signed_model.sig_path),
            "--trust-config", str(path),
        ],
    )  # fmt: skip
    assert out.exit_code == 2
    assert "expired at" in out.output


def test_verify_reports_conflicting_fingerprint_sources_as_an_error(
    signed_model: SignedModel, tmp_path: Path
) -> None:
    path = _write(
        tmp_path / "trust.yaml",
        f"keys:\n  - key_id: '{signed_model.fingerprint}'\n    label: from-file\n",
    )
    out = CliRunner().invoke(
        cli,
        [
            "verify", str(signed_model.artifact),
            "--mbom", str(signed_model.mbom_path),
            "--signature", str(signed_model.sig_path),
            "--trust-config", str(path),
            "--trusted-fingerprint", signed_model.fingerprint,
        ],
    )  # fmt: skip
    # Same fingerprint, but the CLI-supplied entry is unconstrained while the
    # file's entry has a label -- these are NOT equal TrustedKeyEntry objects,
    # so this is a genuine conflict and must be refused, not silently merged.
    assert out.exit_code == 1
    assert "configured more than once" in out.output


def test_policy_check_honors_trust_config(signed_model: SignedModel, tmp_path: Path) -> None:
    path = _write(tmp_path / "trust.yaml", f"keys:\n  - key_id: '{signed_model.fingerprint}'\n")
    out = CliRunner().invoke(
        cli,
        [
            "policy", "check", str(signed_model.artifact),
            "--mbom", str(signed_model.mbom_path),
            "--signature", str(signed_model.sig_path),
            "--policy", str(signed_model.policy_path),
            "--trust-config", str(path),
        ],
    )  # fmt: skip
    assert out.exit_code == 0
    assert "ALLOW" in out.output
