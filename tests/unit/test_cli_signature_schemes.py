"""CLI coverage: --reject-legacy-signatures and the new verify output fields."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from modelguard.cli.main import cli
from tests.conftest import SignedModel

FIXTURE = Path(__file__).parent.parent / "fixtures" / "legacy_signature_0_6_0"


def test_verify_json_reports_algorithm_and_key_fingerprint(signed_model: SignedModel) -> None:
    out = CliRunner().invoke(
        cli,
        [
            "verify", str(signed_model.artifact),
            "--mbom", str(signed_model.mbom_path),
            "--signature", str(signed_model.sig_path),
            "--format", "json",
        ],
    )  # fmt: skip
    payload = json.loads(out.output)
    assert payload["signature_algorithm"] == "ed25519"
    assert payload["signer_key_fingerprint"] == signed_model.fingerprint


def test_verify_text_output_includes_algorithm_and_key(signed_model: SignedModel) -> None:
    out = CliRunner().invoke(
        cli,
        [
            "verify", str(signed_model.artifact),
            "--mbom", str(signed_model.mbom_path),
            "--signature", str(signed_model.sig_path),
        ],
    )  # fmt: skip
    assert "Algorithm    : ed25519" in out.output
    assert f"Key          : {signed_model.fingerprint}" in out.output


def test_legacy_fixture_verifies_by_default() -> None:
    out = CliRunner().invoke(
        cli,
        [
            "verify", str(FIXTURE / "model"),
            "--mbom", str(FIXTURE / "model.bom.json"),
            "--signature", str(FIXTURE / "model.sig.json"),
        ],
    )  # fmt: skip
    assert out.exit_code == 0
    assert "ALLOWED" in out.output


def test_reject_legacy_signatures_denies_the_0_6_0_fixture() -> None:
    out = CliRunner().invoke(
        cli,
        [
            "verify", str(FIXTURE / "model"),
            "--mbom", str(FIXTURE / "model.bom.json"),
            "--signature", str(FIXTURE / "model.sig.json"),
            "--reject-legacy-signatures",
        ],
    )  # fmt: skip
    assert out.exit_code == 2
    assert "DENIED" in out.output


def test_reject_legacy_signatures_also_applies_to_policy_check() -> None:
    policy = FIXTURE / "reject_legacy.policy.yaml"
    policy.write_text("policy:\n  name: strict\nrules:\n  require_valid_signature: {enabled: true, on_fail: deny}\n")
    try:
        out = CliRunner().invoke(
            cli,
            [
                "policy", "check", str(FIXTURE / "model"),
                "--mbom", str(FIXTURE / "model.bom.json"),
                "--signature", str(FIXTURE / "model.sig.json"),
                "--policy", str(policy),
                "--reject-legacy-signatures",
            ],
        )  # fmt: skip
        assert out.exit_code == 2
    finally:
        policy.unlink()


def test_reject_legacy_signatures_does_not_affect_v2_signatures(signed_model: SignedModel) -> None:
    out = CliRunner().invoke(
        cli,
        [
            "verify", str(signed_model.artifact),
            "--mbom", str(signed_model.mbom_path),
            "--signature", str(signed_model.sig_path),
            "--reject-legacy-signatures",
        ],
    )  # fmt: skip
    assert out.exit_code == 0
