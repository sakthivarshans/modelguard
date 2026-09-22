"""Security tests: hostile signature files and envelope loading.

These attack the *parsing* boundary (before any crypto runs) and the
*structural binding* between the unsigned ``signature_type`` and the
signed ``signature_algorithm``.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from modelguard.exceptions import (
    MalformedSignatureError,
    SignatureInvalidError,
    UnsupportedSignatureSchemeError,
)
from modelguard.signing.envelope import MAX_ENVELOPE_BYTES, SignaturePayload, load_envelope
from modelguard.signing.keys import generate_keypair
from modelguard.signing.providers import LocalEd25519Signer
from modelguard.signing.schemes import ALGORITHM_ECDSA_P256_SHA256, ALGORITHM_ED25519
from modelguard.signing.signer import sign_artifact, sign_with_provider
from modelguard.signing.verifier import verify_envelope_signature
from tests.signing_helpers import Model, SoftwareP256Signer, make_model, sign_raw


@pytest.fixture
def model(tmp_path: Path) -> Model:
    return make_model(tmp_path)


def test_non_json_file_is_refused_cleanly(tmp_path: Path) -> None:
    path = tmp_path / "sig.json"
    path.write_text("not json at all {{{")
    with pytest.raises(MalformedSignatureError):
        load_envelope(path)


def test_oversized_file_is_rejected_before_json_parsing(tmp_path: Path) -> None:
    path = tmp_path / "sig.json"
    path.write_bytes(b"[" + b"0," * (MAX_ENVELOPE_BYTES) + b"0]")
    with pytest.raises(MalformedSignatureError, match="larger than"):
        load_envelope(path)


def test_deeply_nested_json_does_not_crash_the_process(tmp_path: Path) -> None:
    path = tmp_path / "sig.json"
    path.write_text("[" * 5000 + "]" * 5000)
    with pytest.raises(MalformedSignatureError):
        load_envelope(path)


def test_unknown_top_level_field_is_rejected(tmp_path: Path, model: Model) -> None:
    keypair = generate_keypair("a@x.com")
    envelope = sign_artifact(model.manifest, model.mbom, keypair)
    data = json.loads(envelope.to_json())
    data["extra_field"] = "injected"
    path = tmp_path / "sig.json"
    path.write_text(json.dumps(data))
    with pytest.raises(MalformedSignatureError):
        load_envelope(path)


def test_unknown_payload_field_is_rejected(tmp_path: Path, model: Model) -> None:
    keypair = generate_keypair("a@x.com")
    envelope = sign_artifact(model.manifest, model.mbom, keypair)
    data = json.loads(envelope.to_json())
    data["payload"]["admin"] = True
    path = tmp_path / "sig.json"
    path.write_text(json.dumps(data))
    with pytest.raises(MalformedSignatureError):
        load_envelope(path)


def test_non_utf8_bytes_are_refused_cleanly(tmp_path: Path) -> None:
    path = tmp_path / "sig.json"
    path.write_bytes(b"\xff\xfe\x00\x01garbage")
    with pytest.raises(MalformedSignatureError):
        load_envelope(path)


def test_unreadable_signature_field_type_is_rejected(tmp_path: Path, model: Model) -> None:
    keypair = generate_keypair("a@x.com")
    envelope = sign_artifact(model.manifest, model.mbom, keypair)
    data = json.loads(envelope.to_json())
    data["signature"] = 12345  # not a string
    path = tmp_path / "sig.json"
    path.write_text(json.dumps(data))
    with pytest.raises(MalformedSignatureError):
        load_envelope(path)


# --- Algorithm confusion / downgrade -----------------------------------------


def test_unsigned_label_disagreeing_with_signed_algorithm_is_refused(model: Model) -> None:
    """Relabeling the unsigned signature_type must not change what verifies."""
    signer = SoftwareP256Signer()
    envelope = sign_with_provider(model.manifest, model.mbom, signer)
    assert envelope.payload.signature_algorithm == ALGORITHM_ECDSA_P256_SHA256

    tampered = envelope.model_copy(update={"signature_type": ALGORITHM_ED25519})
    with pytest.raises(SignatureInvalidError, match="labels the signature"):
        verify_envelope_signature(tampered)


def test_a_v1_shaped_signature_cannot_claim_to_be_a_stronger_scheme(model: Model) -> None:
    """Downgrade in the other direction: no signed algorithm, but claim ed25519-local
    while actually holding P-256 key/signature bytes; must fail on crypto, not on trust."""
    signer = SoftwareP256Signer()
    p = SignaturePayload(
        schema_version="1",
        artifact_digest=f"{model.manifest.algorithm}:{model.manifest.digest}",
        mbom_digest=f"sha256:{hashlib.sha256(model.mbom.canonical_json()).hexdigest()}",
        model_id=model.manifest.model_id,
        version=model.manifest.version,
        signer_identity="attacker@example.com",
        signed_at=datetime.now(UTC).isoformat(),
    )
    envelope = sign_raw(p, signer, signature_type="ed25519-local")
    with pytest.raises(SignatureInvalidError):
        verify_envelope_signature(envelope)


def test_unknown_signature_algorithm_in_v2_payload_fails_closed(model: Model) -> None:
    keypair = generate_keypair("a@x.com")
    envelope = sign_artifact(model.manifest, model.mbom, keypair)
    tampered_payload = envelope.payload.model_copy(update={"signature_algorithm": "rsa-4096"})
    tampered = envelope.model_copy(update={"payload": tampered_payload, "signature_type": "rsa-4096"})
    with pytest.raises(UnsupportedSignatureSchemeError):
        verify_envelope_signature(tampered)


def test_unknown_schema_version_fails_closed(model: Model) -> None:
    keypair = generate_keypair("a@x.com")
    envelope = sign_artifact(model.manifest, model.mbom, keypair)
    tampered_payload = envelope.payload.model_copy(update={"schema_version": "99"})
    tampered = envelope.model_copy(update={"payload": tampered_payload})
    with pytest.raises(UnsupportedSignatureSchemeError):
        verify_envelope_signature(tampered)


def test_v1_payload_carrying_v2_fields_is_rejected(model: Model) -> None:
    keypair = generate_keypair("a@x.com")
    envelope = sign_artifact(model.manifest, model.mbom, keypair)
    # Force it back to v1 shape but leave the v2 fields populated (should never
    # happen from the signer, but a hand-crafted file could try this).
    tampered_payload = envelope.payload.model_copy(update={"schema_version": "1"})
    tampered = envelope.model_copy(update={"payload": tampered_payload})
    with pytest.raises(SignatureInvalidError, match="must not carry"):
        verify_envelope_signature(tampered)


def test_legacy_v1_can_be_refused_by_policy(model: Model) -> None:

    from modelguard.signing.keys import generate_keypair as gk

    keypair = gk("a@x.com")
    p = SignaturePayload(
        schema_version="1",
        artifact_digest=f"{model.manifest.algorithm}:{model.manifest.digest}",
        mbom_digest=f"sha256:{hashlib.sha256(model.mbom.canonical_json()).hexdigest()}",
        model_id=model.manifest.model_id,
        version=model.manifest.version,
        signer_identity="a@x.com",
        signed_at=datetime.now(UTC).isoformat(),
    )

    envelope = sign_raw(p, LocalEd25519Signer(keypair), signature_type="ed25519-local")
    verify_envelope_signature(envelope)  # allowed by default
    with pytest.raises(UnsupportedSignatureSchemeError, match="legacy"):
        verify_envelope_signature(envelope, allow_legacy_v1=False)


# --- Key substitution ----------------------------------------------------------


def test_key_id_bound_payload_rejects_a_substituted_public_key(model: Model) -> None:
    """The classic KMS-alias-repointed attack: swap the public key in the envelope
    for a different key whose signature happens to also be valid for THAT key --
    the payload's key_id must catch the swap even though the crypto alone would not."""
    signer_a = SoftwareP256Signer()
    signer_b = SoftwareP256Signer()
    envelope = sign_with_provider(model.manifest, model.mbom, signer_a)

    # Re-sign the same payload with signer_b, then graft signer_a's key_id-bearing
    # payload onto signer_b's signature/key -- i.e. present signer_b's material
    # under a payload that claims to be signer_a's key.
    forged = envelope.model_copy(
        update={
            "signature": signer_b.sign(envelope.payload.canonical_json()).hex(),
            "public_key": signer_b.public_key().hex(),
        }
    )
    with pytest.raises(SignatureInvalidError, match="key was substituted"):
        verify_envelope_signature(forged)


def test_v1_payload_with_a_relabeled_signature_type_is_refused(model: Model) -> None:
    """A legacy payload signed correctly, but the unsigned signature_type field
    relabeled to something else, must still fail closed (nothing signs that field
    in format version 1, so this is exactly the case the fixed value guards)."""
    keypair = generate_keypair("a@x.com")
    envelope = sign_artifact(model.manifest, model.mbom, keypair)
    # Downgrade the crafted envelope to a v1-shaped payload with a relabeled type.
    v1_payload = envelope.payload.model_copy(
        update={"schema_version": "1", "signature_algorithm": None, "key_id": None}
    )
    tampered = envelope.model_copy(update={"payload": v1_payload, "signature_type": "not-a-real-scheme"})
    with pytest.raises(UnsupportedSignatureSchemeError, match="Unsupported legacy signature_type"):
        verify_envelope_signature(tampered)
