"""Signatures written by 0.6.0 must keep verifying.

The fixture in ``tests/fixtures/legacy_signature_0_6_0`` was produced by
the unmodified 0.6.0 signer before any Phase 7 change. It must never be
regenerated with current code.
"""

from __future__ import annotations

import json
from pathlib import Path

from modelguard.sdk import ModelGuard
from modelguard.signing.envelope import load_envelope
from modelguard.signing.verifier import verify_envelope_signature

FIXTURE = Path(__file__).parent.parent / "fixtures" / "legacy_signature_0_6_0"
FINGERPRINT = (FIXTURE / "FINGERPRINT").read_text().strip()


def test_the_fixture_really_is_a_legacy_format_version_1_envelope() -> None:
    data = json.loads((FIXTURE / "model.sig.json").read_text())
    assert data["payload"]["schema_version"] == "1"
    assert data["signature_type"] == "ed25519-local"
    assert "key_id" not in data["payload"]
    assert "signature_algorithm" not in data["payload"]


def test_legacy_canonical_bytes_are_unchanged_by_the_new_optional_fields() -> None:
    envelope = load_envelope(FIXTURE / "model.sig.json")
    canonical = envelope.payload.canonical_json().decode()
    assert "key_id" not in canonical
    assert "signature_algorithm" not in canonical


def test_legacy_signature_verifies_and_is_reported_as_unbound() -> None:
    envelope = load_envelope(FIXTURE / "model.sig.json")
    check = verify_envelope_signature(envelope)
    assert check.format_version == "1"
    assert check.algorithm == "ed25519"
    assert check.key_bound is False
    assert check.key_fingerprint == FINGERPRINT


def test_legacy_signature_passes_full_sdk_verification_with_trust_root() -> None:
    result = ModelGuard(trusted_key_fingerprints=[FINGERPRINT]).verify(
        FIXTURE / "model", FIXTURE / "model.bom.json", FIXTURE / "model.sig.json"
    )
    assert result.allowed is True
    assert result.digest_matches is True
    assert result.signer_trusted is True
    assert result.signature_algorithm == "ed25519"
    assert result.signer_key_fingerprint == FINGERPRINT


def test_legacy_signature_is_refused_when_configured_to_reject_legacy() -> None:
    result = ModelGuard(allow_legacy_signatures=False).verify(
        FIXTURE / "model", FIXTURE / "model.bom.json", FIXTURE / "model.sig.json"
    )
    assert result.allowed is False
    assert result.signature_valid is False
    assert any("legacy" in r for r in result.reasons)
