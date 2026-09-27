"""CLI coverage: `modelguard trust add-key/retire-key/revoke-key/remove-key`.

Includes explicit regression tests for two bugs found by manually
exercising this workflow end to end before writing these tests:
(1) retire-key/revoke-key used to bypass pydantic validation entirely
via `model_copy(update=...)`, so a CLI-supplied `--not-after` string
was stored unvalidated instead of becoming a real, checked `datetime`;
(2) every mutation command let a raw `pydantic.ValidationError` escape
as an unhandled traceback instead of a clean `Error: ...` message.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from click.testing import CliRunner

from modelguard.cli.main import cli
from modelguard.signing.trust_config import load_trust_config_file

FP_A = "a" * 64
FP_B = "b" * 64


def _run(*args: str) -> object:
    return CliRunner().invoke(cli, list(args))


def test_add_key_creates_a_new_file(tmp_path: Path) -> None:
    path = tmp_path / "trust.yaml"
    out = _run("trust", "add-key", str(path), "--key-id", FP_A, "--label", "prod")
    assert out.exit_code == 0
    config = load_trust_config_file(path)
    assert config.keys[0].key_id == FP_A
    assert config.keys[0].label == "prod"


def test_add_key_appends_to_an_existing_file(tmp_path: Path) -> None:
    path = tmp_path / "trust.yaml"
    _run("trust", "add-key", str(path), "--key-id", FP_A)
    _run("trust", "add-key", str(path), "--key-id", FP_B)
    config = load_trust_config_file(path)
    assert {k.key_id for k in config.keys} == {FP_A, FP_B}


def test_add_key_rejects_a_duplicate_fingerprint_cleanly(tmp_path: Path) -> None:
    path = tmp_path / "trust.yaml"
    _run("trust", "add-key", str(path), "--key-id", FP_A)
    out = _run("trust", "add-key", str(path), "--key-id", FP_A, "--label", "dup")
    assert out.exit_code == 1
    assert "Error:" in out.output
    assert "Traceback" not in out.output
    assert "Duplicate trust configuration entry" in out.output


def test_add_key_rejects_a_malformed_fingerprint_cleanly(tmp_path: Path) -> None:
    path = tmp_path / "trust.yaml"
    out = _run("trust", "add-key", str(path), "--key-id", "not-a-fingerprint")
    assert out.exit_code == 1
    assert "Error:" in out.output
    assert "Traceback" not in out.output
    assert not path.exists()


def test_retire_key_sets_status_and_leaves_other_fields_intact(tmp_path: Path) -> None:
    path = tmp_path / "trust.yaml"
    _run("trust", "add-key", str(path), "--key-id", FP_A, "--label", "old")
    out = _run("trust", "retire-key", str(path), "--key-id", FP_A)
    assert out.exit_code == 0
    config = load_trust_config_file(path)
    assert config.keys[0].status.value == "retired"
    assert config.keys[0].label == "old"  # unrelated field preserved


def test_retire_key_with_not_after_produces_a_real_validated_datetime(tmp_path: Path) -> None:
    """Regression test: retire-key must not bypass validation. Confirms
    not_after round-trips as an actual timezone-aware datetime, not a
    raw unvalidated string, by loading the file back through the real
    schema (which would reject a raw/naive string) and checking the
    parsed type."""
    path = tmp_path / "trust.yaml"
    _run("trust", "add-key", str(path), "--key-id", FP_A)
    out = _run("trust", "retire-key", str(path), "--key-id", FP_A, "--not-after", "2027-01-01T00:00:00Z")
    assert out.exit_code == 0

    # The raw YAML must contain a normalized, quoted ISO timestamp with an
    # explicit offset -- not the literal string handed to the CLI passed
    # through untouched in some other shape.
    raw = yaml.safe_load(path.read_text())
    assert raw["keys"][0]["not_after"] == "2027-01-01T00:00:00Z"

    config = load_trust_config_file(path)
    assert config.keys[0].not_after is not None
    assert config.keys[0].not_after.tzinfo is not None


def test_retire_key_rejects_a_naive_not_after_cleanly(tmp_path: Path) -> None:
    """Regression test: before the fix, a naive timestamp was silently
    accepted by model_copy(update=...) because validation never ran."""
    path = tmp_path / "trust.yaml"
    _run("trust", "add-key", str(path), "--key-id", FP_A)
    out = _run("trust", "retire-key", str(path), "--key-id", FP_A, "--not-after", "2027-01-01T00:00:00")
    assert out.exit_code == 1
    assert "Error:" in out.output
    assert "Traceback" not in out.output
    assert "UTC offset" in out.output
    # The file must be unchanged -- no partial/invalid write.
    config = load_trust_config_file(path)
    assert config.keys[0].status.value == "active"
    assert config.keys[0].not_after is None


def test_retire_key_on_a_nonexistent_fingerprint_fails_cleanly(tmp_path: Path) -> None:
    path = tmp_path / "trust.yaml"
    _run("trust", "add-key", str(path), "--key-id", FP_A)
    out = _run("trust", "retire-key", str(path), "--key-id", FP_B)
    assert out.exit_code == 1
    assert "No entry with fingerprint" in out.output


def test_revoke_key_sets_status(tmp_path: Path) -> None:
    path = tmp_path / "trust.yaml"
    _run("trust", "add-key", str(path), "--key-id", FP_A)
    out = _run("trust", "revoke-key", str(path), "--key-id", FP_A)
    assert out.exit_code == 0
    config = load_trust_config_file(path)
    assert config.keys[0].status.value == "revoked"


def test_remove_key_deletes_the_entry_entirely(tmp_path: Path) -> None:
    path = tmp_path / "trust.yaml"
    _run("trust", "add-key", str(path), "--key-id", FP_A)
    _run("trust", "add-key", str(path), "--key-id", FP_B)
    out = _run("trust", "remove-key", str(path), "--key-id", FP_A)
    assert out.exit_code == 0
    config = load_trust_config_file(path)
    assert {k.key_id for k in config.keys} == {FP_B}


def test_remove_key_on_a_nonexistent_fingerprint_fails_cleanly(tmp_path: Path) -> None:
    path = tmp_path / "trust.yaml"
    _run("trust", "add-key", str(path), "--key-id", FP_A)
    out = _run("trust", "remove-key", str(path), "--key-id", FP_B)
    assert out.exit_code == 1
    assert "No entry with fingerprint" in out.output


def test_a_full_rotation_workflow_end_to_end(tmp_path: Path) -> None:
    """add new key -> retire old key with an expiry -> remove the old key
    once its retirement window has been recorded elsewhere."""
    path = tmp_path / "trust.yaml"
    _run("trust", "add-key", str(path), "--key-id", FP_A, "--label", "2025 key")
    _run("trust", "add-key", str(path), "--key-id", FP_B, "--label", "2026 key")
    _run("trust", "retire-key", str(path), "--key-id", FP_A, "--not-after", "2026-06-01T00:00:00Z")
    config = load_trust_config_file(path)
    by_id = {k.key_id: k for k in config.keys}
    assert by_id[FP_A].status.value == "retired"
    assert by_id[FP_B].status.value == "active"

    _run("trust", "remove-key", str(path), "--key-id", FP_A)
    config = load_trust_config_file(path)
    assert {k.key_id for k in config.keys} == {FP_B}


def test_key_id_accepts_sha256_prefix_on_the_cli(tmp_path: Path) -> None:
    path = tmp_path / "trust.yaml"
    out = _run("trust", "add-key", str(path), "--key-id", f"sha256:{FP_A}")
    assert out.exit_code == 0
    config = load_trust_config_file(path)
    assert config.keys[0].key_id == FP_A  # normalized, prefix stripped


def test_add_key_with_scope_and_algorithm(tmp_path: Path) -> None:
    path = tmp_path / "trust.yaml"
    out = _run(
        "trust", "add-key", str(path),
        "--key-id", FP_A,
        "--algorithm", "ecdsa-p256-sha256",
        "--scope", "prod-*",
        "--scope", "staging-*",
        "--signer-identity", "ci@example.com",
    )  # fmt: skip
    assert out.exit_code == 0
    config = load_trust_config_file(path)
    key = config.keys[0]
    assert key.algorithm == "ecdsa-p256-sha256"
    assert set(key.scope_model_id_patterns) == {"prod-*", "staging-*"}
    assert key.signer_identity == "ci@example.com"
