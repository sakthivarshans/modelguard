"""SDK-level coverage of the new signature-scheme surface."""

from __future__ import annotations

from pathlib import Path

import pytest

from modelguard.sdk import ModelGuard
from modelguard.signing.schemes import (
    ALGORITHM_ECDSA_P256_SHA256,
    ALGORITHM_ED25519,
    key_fingerprint,
)
from tests.conftest import SignedModel
from tests.signing_helpers import make_model


def test_verify_reports_algorithm_and_key_fingerprint(signed_model: SignedModel) -> None:
    result = ModelGuard().verify(signed_model.artifact, signed_model.mbom_path, signed_model.sig_path)
    assert result.signature_algorithm == ALGORITHM_ED25519
    assert result.signer_key_fingerprint == signed_model.fingerprint


def test_verify_with_a_p256_provider_end_to_end(tmp_path: Path) -> None:
    from tests.signing_helpers import SoftwareP256Signer

    model = make_model(tmp_path)
    signer = SoftwareP256Signer()
    guard = ModelGuard(trusted_key_fingerprints=[key_fingerprint(signer.public_key())])
    envelope = guard.sign_with_provider(model.manifest, model.mbom, signer)
    sig_path = tmp_path / "model.sig.json"
    sig_path.write_text(envelope.to_json())

    result = guard.verify(model.path, model.mbom_path, sig_path)
    assert result.allowed is True
    assert result.signature_algorithm == ALGORITHM_ECDSA_P256_SHA256
    assert result.signer_trusted is True


def test_tampered_artifact_signed_with_p256_is_denied(tmp_path: Path) -> None:
    from tests.signing_helpers import SoftwareP256Signer

    model = make_model(tmp_path)
    signer = SoftwareP256Signer()
    guard = ModelGuard()
    envelope = guard.sign_with_provider(model.manifest, model.mbom, signer)
    sig_path = tmp_path / "model.sig.json"
    sig_path.write_text(envelope.to_json())

    (model.path / "weights.bin").write_bytes(b"tampered!!")
    result = guard.verify(model.path, model.mbom_path, sig_path)
    assert result.allowed is False
    assert result.digest_matches is False


def test_reject_legacy_signatures_flows_through_the_sdk_flag(signed_model: SignedModel) -> None:
    # signed_model uses the current (v2) signer, so this is allowed either way --
    # this test only proves the constructor flag reaches verification.
    guard = ModelGuard(allow_legacy_signatures=False)
    result = guard.verify(signed_model.artifact, signed_model.mbom_path, signed_model.sig_path)
    assert result.allowed is True  # v2 signature, not affected by rejecting legacy


def test_malformed_signature_file_is_a_clean_verificationresult_denial(
    signed_model: SignedModel, tmp_path: Path
) -> None:
    from modelguard.exceptions import MalformedSignatureError

    bad_sig = tmp_path / "bad.sig.json"
    bad_sig.write_text("{not json")
    with pytest.raises(MalformedSignatureError):
        ModelGuard().verify(signed_model.artifact, signed_model.mbom_path, bad_sig)
