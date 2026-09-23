"""SDK-level coverage of TrustConfig integration in ModelGuard.verify()."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from modelguard.exceptions import TrustConfigurationError
from modelguard.sdk import ModelGuard
from modelguard.signing.trust_config import TrustConfig, TrustedKeyEntry, TrustedKeyStatus
from tests.conftest import SignedModel


def test_verify_trusts_via_trust_config(signed_model: SignedModel) -> None:
    config = TrustConfig(keys=(TrustedKeyEntry(key_id=signed_model.fingerprint),))
    guard = ModelGuard(trust_config=config)
    result = guard.verify(signed_model.artifact, signed_model.mbom_path, signed_model.sig_path)
    assert result.allowed is True
    assert result.signer_trusted is True


def test_verify_denies_when_key_is_revoked_in_trust_config(signed_model: SignedModel) -> None:
    config = TrustConfig(
        keys=(TrustedKeyEntry(key_id=signed_model.fingerprint, status=TrustedKeyStatus.REVOKED),)
    )
    guard = ModelGuard(trust_config=config)
    result = guard.verify(signed_model.artifact, signed_model.mbom_path, signed_model.sig_path)
    assert result.allowed is False
    assert result.signer_trusted is False
    assert any("revoked" in r for r in result.reasons)


def test_verify_denies_when_key_is_expired(signed_model: SignedModel) -> None:
    config = TrustConfig(
        keys=(
            TrustedKeyEntry(
                key_id=signed_model.fingerprint, not_after=datetime(2000, 1, 1, tzinfo=UTC)
            ),
        )
    )
    guard = ModelGuard(trust_config=config)
    result = guard.verify(signed_model.artifact, signed_model.mbom_path, signed_model.sig_path)
    assert result.allowed is False
    assert any("expired" in r for r in result.reasons)


def test_verify_trusts_within_a_validity_window(signed_model: SignedModel) -> None:
    now = datetime.now(UTC)
    config = TrustConfig(
        keys=(
            TrustedKeyEntry(
                key_id=signed_model.fingerprint,
                not_before=now - timedelta(days=1),
                not_after=now + timedelta(days=1),
            ),
        )
    )
    guard = ModelGuard(trust_config=config)
    result = guard.verify(signed_model.artifact, signed_model.mbom_path, signed_model.sig_path)
    assert result.allowed is True


def test_verify_scopes_trust_to_matching_model_id(signed_model: SignedModel) -> None:
    """signed_model's manifest uses model_id 'demo' (see build_signed_model)."""
    matching = TrustConfig(
        keys=(TrustedKeyEntry(key_id=signed_model.fingerprint, scope_model_id_patterns=("demo",)),)
    )
    mismatching = TrustConfig(
        keys=(
            TrustedKeyEntry(key_id=signed_model.fingerprint, scope_model_id_patterns=("other-*",)),
        )
    )
    assert ModelGuard(trust_config=matching).verify(
        signed_model.artifact, signed_model.mbom_path, signed_model.sig_path
    ).allowed is True
    assert ModelGuard(trust_config=mismatching).verify(
        signed_model.artifact, signed_model.mbom_path, signed_model.sig_path
    ).allowed is False


def test_verify_denies_when_signer_identity_binding_mismatches(signed_model: SignedModel) -> None:
    config = TrustConfig(
        keys=(
            TrustedKeyEntry(
                key_id=signed_model.fingerprint, signer_identity="someone-else@example.com"
            ),
        )
    )
    guard = ModelGuard(trust_config=config)
    result = guard.verify(signed_model.artifact, signed_model.mbom_path, signed_model.sig_path)
    assert result.allowed is False
    assert any("bound to signer identity" in r for r in result.reasons)


def test_trusted_key_fingerprints_and_trust_config_combine(signed_model: SignedModel) -> None:
    other_fp = "b" * 64
    guard = ModelGuard(
        trusted_key_fingerprints=[other_fp],
        trust_config=TrustConfig(keys=(TrustedKeyEntry(key_id=signed_model.fingerprint),)),
    )
    assert guard.trusted_key_fingerprints == frozenset({other_fp, signed_model.fingerprint})
    result = guard.verify(signed_model.artifact, signed_model.mbom_path, signed_model.sig_path)
    assert result.allowed is True


def test_conflicting_fingerprint_across_sources_raises_at_construction(
    signed_model: SignedModel,
) -> None:
    with pytest.raises(TrustConfigurationError, match="configured more than once"):
        ModelGuard(
            trusted_key_fingerprints=[signed_model.fingerprint],
            trust_config=TrustConfig(
                keys=(TrustedKeyEntry(key_id=signed_model.fingerprint, label="different"),)
            ),
        )


def test_trust_config_property_exposes_the_merged_config(signed_model: SignedModel) -> None:
    config = TrustConfig(keys=(TrustedKeyEntry(key_id=signed_model.fingerprint, label="prod"),))
    guard = ModelGuard(trust_config=config)
    assert guard.trust_config is not None
    assert guard.trust_config.keys[0].label == "prod"


def test_no_trust_configured_reports_none(signed_model: SignedModel) -> None:
    guard = ModelGuard()
    assert guard.trust_config is None
    assert guard.trusted_key_fingerprints is None
    result = guard.verify(signed_model.artifact, signed_model.mbom_path, signed_model.sig_path)
    assert result.signer_trusted is None
    assert result.allowed is True  # signature/digest/mbom valid; trust simply not checked
