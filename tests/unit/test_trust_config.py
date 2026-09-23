"""Unit tests for the trust configuration model, loader, and evaluation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from modelguard.exceptions import TrustConfigurationError
from modelguard.signing.trust_config import (
    TrustConfig,
    TrustedKeyEntry,
    TrustedKeyStatus,
    build_minimal_trust_config,
    evaluate_trust,
    load_trust_config_file,
    merge_trust_configs,
)

FP_A = "a" * 64
FP_B = "b" * 64
NOW = datetime(2026, 6, 1, tzinfo=UTC)


# --- TrustedKeyEntry validation ------------------------------------------------


def test_key_id_accepts_sha256_prefix_and_normalizes_case() -> None:
    entry = TrustedKeyEntry(key_id=f"sha256:{FP_A.upper()}")
    assert entry.key_id == FP_A


@pytest.mark.parametrize("bad", ["not-hex", "a" * 63, "a" * 65, "", "g" * 64])
def test_key_id_rejects_malformed_fingerprints(bad: str) -> None:
    with pytest.raises(ValidationError):
        TrustedKeyEntry(key_id=bad)


@pytest.mark.parametrize("algo", ["Ed25519", "ed_25519", "-ed25519", "a" * 65, ""])
def test_algorithm_rejects_invalid_identifiers(algo: str) -> None:
    with pytest.raises(ValidationError):
        TrustedKeyEntry(key_id=FP_A, algorithm=algo)


def test_algorithm_accepts_a_valid_identifier() -> None:
    assert TrustedKeyEntry(key_id=FP_A, algorithm="ecdsa-p256-sha256").algorithm == "ecdsa-p256-sha256"


def test_naive_not_before_is_rejected() -> None:
    with pytest.raises(ValidationError, match="explicit UTC offset"):
        TrustedKeyEntry(key_id=FP_A, not_before=datetime(2026, 1, 1))  # noqa: DTZ001


def test_naive_not_after_is_rejected() -> None:
    with pytest.raises(ValidationError, match="explicit UTC offset"):
        TrustedKeyEntry(key_id=FP_A, not_after=datetime(2026, 1, 1))  # noqa: DTZ001


def test_not_before_after_not_after_is_rejected() -> None:
    with pytest.raises(ValidationError, match="must not be after"):
        TrustedKeyEntry(
            key_id=FP_A,
            not_before=datetime(2026, 6, 1, tzinfo=UTC),
            not_after=datetime(2026, 1, 1, tzinfo=UTC),
        )


def test_equal_not_before_and_not_after_is_allowed() -> None:
    t = datetime(2026, 1, 1, tzinfo=UTC)
    TrustedKeyEntry(key_id=FP_A, not_before=t, not_after=t)  # should not raise


@pytest.mark.parametrize("field", ["signer_identity", "label"])
def test_bounded_string_fields_reject_empty_and_oversized(field: str) -> None:
    with pytest.raises(ValidationError):
        TrustedKeyEntry(key_id=FP_A, **{field: ""})
    with pytest.raises(ValidationError):
        TrustedKeyEntry(key_id=FP_A, **{field: "x" * 201})


@pytest.mark.parametrize("field", ["signer_identity", "label"])
def test_bounded_string_fields_reject_control_characters(field: str) -> None:
    with pytest.raises(ValidationError, match="control characters"):
        TrustedKeyEntry(key_id=FP_A, **{field: "line1\nline2"})


def test_scope_patterns_reject_too_many() -> None:
    with pytest.raises(ValidationError, match="at most"):
        TrustedKeyEntry(key_id=FP_A, scope_model_id_patterns=tuple(f"p{i}" for i in range(33)))


def test_scope_patterns_reject_empty_entry() -> None:
    with pytest.raises(ValidationError):
        TrustedKeyEntry(key_id=FP_A, scope_model_id_patterns=("",))


def test_unknown_field_is_rejected() -> None:
    with pytest.raises(ValidationError):
        TrustedKeyEntry.model_validate({"key_id": FP_A, "not_a_real_field": True})


def test_entry_is_frozen() -> None:
    entry = TrustedKeyEntry(key_id=FP_A)
    with pytest.raises(ValidationError):
        entry.status = TrustedKeyStatus.REVOKED  # type: ignore[misc]


# --- TrustConfig ---------------------------------------------------------------


def test_duplicate_key_id_is_rejected() -> None:
    with pytest.raises(ValidationError, match="Duplicate trust configuration entry"):
        TrustConfig(keys=(TrustedKeyEntry(key_id=FP_A), TrustedKeyEntry(key_id=FP_A, label="x")))


def test_empty_trust_config_is_valid_and_trusts_nothing() -> None:
    config = TrustConfig()
    assert config.keys == ()
    evaluation = evaluate_trust(FP_A, "ed25519", config, now=NOW)
    assert evaluation.trusted is False


def test_unknown_top_level_field_is_rejected() -> None:
    with pytest.raises(ValidationError):
        TrustConfig.model_validate({"keys": [], "unexpected": 1})


# --- evaluate_trust --------------------------------------------------------------


def test_unknown_fingerprint_is_not_trusted() -> None:
    config = TrustConfig(keys=(TrustedKeyEntry(key_id=FP_A),))
    evaluation = evaluate_trust(FP_B, "ed25519", config, now=NOW)
    assert evaluation.trusted is False
    assert evaluation.matched_key is None
    assert "No trusted key is configured" in evaluation.reasons[0]


def test_unconstrained_entry_trusts_any_algorithm_and_identity() -> None:
    config = TrustConfig(keys=(TrustedKeyEntry(key_id=FP_A),))
    assert evaluate_trust(FP_A, "ed25519", config, now=NOW).trusted is True
    assert evaluate_trust(FP_A, "ecdsa-p256-sha256", config, now=NOW).trusted is True


def test_algorithm_mismatch_is_refused() -> None:
    config = TrustConfig(keys=(TrustedKeyEntry(key_id=FP_A, algorithm="ed25519"),))
    evaluation = evaluate_trust(FP_A, "ecdsa-p256-sha256", config, now=NOW)
    assert evaluation.trusted is False
    assert "configured for algorithm" in evaluation.reasons[0]


@pytest.mark.parametrize("status", [TrustedKeyStatus.RETIRED, TrustedKeyStatus.REVOKED])
def test_non_active_status_is_refused(status: TrustedKeyStatus) -> None:
    config = TrustConfig(keys=(TrustedKeyEntry(key_id=FP_A, status=status),))
    evaluation = evaluate_trust(FP_A, "ed25519", config, now=NOW)
    assert evaluation.trusted is False
    assert status.value in evaluation.reasons[0]


def test_not_yet_valid_key_is_refused() -> None:
    config = TrustConfig(keys=(TrustedKeyEntry(key_id=FP_A, not_before=NOW + timedelta(days=1)),))
    evaluation = evaluate_trust(FP_A, "ed25519", config, now=NOW)
    assert evaluation.trusted is False
    assert "not valid until" in evaluation.reasons[0]


def test_expired_key_is_refused() -> None:
    config = TrustConfig(keys=(TrustedKeyEntry(key_id=FP_A, not_after=NOW - timedelta(days=1)),))
    evaluation = evaluate_trust(FP_A, "ed25519", config, now=NOW)
    assert evaluation.trusted is False
    assert "expired at" in evaluation.reasons[0]


def test_key_within_its_validity_window_is_trusted() -> None:
    config = TrustConfig(
        keys=(
            TrustedKeyEntry(
                key_id=FP_A, not_before=NOW - timedelta(days=1), not_after=NOW + timedelta(days=1)
            ),
        )
    )
    assert evaluate_trust(FP_A, "ed25519", config, now=NOW).trusted is True


def test_signer_identity_binding_rejects_mismatch() -> None:
    config = TrustConfig(keys=(TrustedKeyEntry(key_id=FP_A, signer_identity="ci@example.com"),))
    ok = evaluate_trust(FP_A, "ed25519", config, claimed_signer_identity="ci@example.com", now=NOW)
    bad = evaluate_trust(FP_A, "ed25519", config, claimed_signer_identity="attacker@evil.com", now=NOW)
    assert ok.trusted is True
    assert bad.trusted is False
    assert "bound to signer identity" in bad.reasons[0]


def test_signer_identity_binding_rejects_missing_claim() -> None:
    config = TrustConfig(keys=(TrustedKeyEntry(key_id=FP_A, signer_identity="ci@example.com"),))
    evaluation = evaluate_trust(FP_A, "ed25519", config, claimed_signer_identity=None, now=NOW)
    assert evaluation.trusted is False


def test_scope_restricts_to_matching_model_id() -> None:
    config = TrustConfig(keys=(TrustedKeyEntry(key_id=FP_A, scope_model_id_patterns=("prod-*",)),))
    assert evaluate_trust(FP_A, "ed25519", config, model_id="prod-classifier", now=NOW).trusted is True
    assert evaluate_trust(FP_A, "ed25519", config, model_id="dev-classifier", now=NOW).trusted is False
    assert evaluate_trust(FP_A, "ed25519", config, model_id=None, now=NOW).trusted is False


def test_scope_is_case_sensitive() -> None:
    config = TrustConfig(keys=(TrustedKeyEntry(key_id=FP_A, scope_model_id_patterns=("Prod-*",)),))
    assert evaluate_trust(FP_A, "ed25519", config, model_id="prod-x", now=NOW).trusted is False
    assert evaluate_trust(FP_A, "ed25519", config, model_id="Prod-x", now=NOW).trusted is True


def test_multiple_failing_conditions_all_appear_in_reasons() -> None:
    config = TrustConfig(
        keys=(
            TrustedKeyEntry(
                key_id=FP_A,
                status=TrustedKeyStatus.REVOKED,
                not_after=NOW - timedelta(days=1),
                signer_identity="ci@example.com",
            ),
        )
    )
    evaluation = evaluate_trust(FP_A, "ed25519", config, claimed_signer_identity="someone-else", now=NOW)
    assert evaluation.trusted is False
    assert len(evaluation.reasons) == 3


def test_now_defaults_to_current_time_when_omitted() -> None:
    config = TrustConfig(keys=(TrustedKeyEntry(key_id=FP_A, not_after=datetime(2000, 1, 1, tzinfo=UTC)),))
    evaluation = evaluate_trust(FP_A, "ed25519", config)  # no now= given
    assert evaluation.trusted is False


# --- Design trap: signed_at is never consulted ---------------------------------


def test_expiry_ignores_any_claimed_signing_time_and_uses_only_the_verifier_clock() -> None:
    """The whole point of evaluate_trust: it takes no signed_at parameter at
    all, so there is no way for a caller to accidentally let a payload's
    self-reported timestamp influence the decision. A key that is expired
    *now* is refused even though nothing here claims to know when the
    signature was actually made."""
    config = TrustConfig(keys=(TrustedKeyEntry(key_id=FP_A, not_after=NOW - timedelta(days=365)),))
    # No matter what a signature might claim about signed_at, only `now` matters.
    assert evaluate_trust(FP_A, "ed25519", config, now=NOW).trusted is False
    assert evaluate_trust(FP_A, "ed25519", config, now=NOW - timedelta(days=1000)).trusted is True


# --- build_minimal_trust_config / merge_trust_configs ---------------------------


def test_build_minimal_trust_config_is_unconstrained() -> None:
    config = build_minimal_trust_config([FP_A])
    key = config.keys[0]
    assert key.status is TrustedKeyStatus.ACTIVE
    assert key.algorithm is None
    assert key.not_before is None and key.not_after is None
    assert evaluate_trust(FP_A, "ecdsa-p256-sha256", config, now=NOW).trusted is True


def test_build_minimal_trust_config_rejects_empty() -> None:
    with pytest.raises(TrustConfigurationError):
        build_minimal_trust_config([])


def test_merge_combines_distinct_keys() -> None:
    merged = merge_trust_configs(
        TrustConfig(keys=(TrustedKeyEntry(key_id=FP_A),)),
        TrustConfig(keys=(TrustedKeyEntry(key_id=FP_B),)),
    )
    assert {k.key_id for k in merged.keys} == {FP_A, FP_B}


def test_merge_allows_identical_duplicate_entries() -> None:
    entry_source = TrustConfig(keys=(TrustedKeyEntry(key_id=FP_A, label="x"),))
    merged = merge_trust_configs(entry_source, entry_source)
    assert len(merged.keys) == 1


def test_merge_rejects_conflicting_duplicate_entries() -> None:
    with pytest.raises(TrustConfigurationError, match="configured more than once"):
        merge_trust_configs(
            TrustConfig(keys=(TrustedKeyEntry(key_id=FP_A, label="one"),)),
            TrustConfig(keys=(TrustedKeyEntry(key_id=FP_A, label="two"),)),
        )


def test_merge_with_no_configs_returns_empty_config() -> None:
    assert merge_trust_configs() == TrustConfig()


# --- load_trust_config_file -----------------------------------------------------


def test_load_valid_yaml_file(tmp_path: Path) -> None:
    path = tmp_path / "trust.yaml"
    path.write_text(f"version: '1'\nkeys:\n  - key_id: '{FP_A}'\n    label: prod\n")
    config = load_trust_config_file(path)
    assert len(config.keys) == 1
    assert config.keys[0].label == "prod"


def test_load_missing_file(tmp_path: Path) -> None:
    with pytest.raises(TrustConfigurationError, match="Cannot read"):
        load_trust_config_file(tmp_path / "nope.yaml")


def test_load_invalid_yaml(tmp_path: Path) -> None:
    path = tmp_path / "trust.yaml"
    path.write_text("keys: [unterminated")
    with pytest.raises(TrustConfigurationError, match="not valid YAML"):
        load_trust_config_file(path)


def test_load_non_mapping_document(tmp_path: Path) -> None:
    path = tmp_path / "trust.yaml"
    path.write_text("- just\n- a\n- list\n")
    with pytest.raises(TrustConfigurationError, match="must be a YAML mapping"):
        load_trust_config_file(path)


def test_load_schema_violation_is_readable(tmp_path: Path) -> None:
    path = tmp_path / "trust.yaml"
    path.write_text("keys:\n  - key_id: not-a-real-fingerprint\n")
    with pytest.raises(TrustConfigurationError, match="failed schema validation"):
        load_trust_config_file(path)


def test_load_accepts_json_too(tmp_path: Path) -> None:
    import json

    path = tmp_path / "trust.json"
    path.write_text(json.dumps({"keys": [{"key_id": FP_A}]}))
    config = load_trust_config_file(path)
    assert config.keys[0].key_id == FP_A
