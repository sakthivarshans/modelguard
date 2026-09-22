"""``sign_with_provider``: the provider contract and fail-closed behavior."""

from __future__ import annotations

from pathlib import Path

import pytest

from modelguard.exceptions import SigningProviderError, UnsupportedSignatureSchemeError
from modelguard.signing.keys import generate_keypair
from modelguard.signing.providers import LocalEd25519Signer
from modelguard.signing.schemes import (
    ALGORITHM_ECDSA_P256_SHA256,
    ALGORITHM_ED25519,
    key_fingerprint,
)
from modelguard.signing.signer import sign_artifact, sign_with_provider
from modelguard.signing.verifier import verify_envelope_signature
from tests.signing_helpers import Model, SoftwareP256Signer, make_model


@pytest.fixture
def model(tmp_path: Path) -> Model:
    return make_model(tmp_path)


def test_sign_artifact_emits_a_bound_v2_envelope(model: Model) -> None:
    keypair = generate_keypair("dev@example.com")
    envelope = sign_artifact(model.manifest, model.mbom, keypair)

    assert envelope.payload.schema_version == "2"
    assert envelope.payload.signature_algorithm == ALGORITHM_ED25519
    assert envelope.signature_type == ALGORITHM_ED25519
    assert envelope.payload.key_id == key_fingerprint(bytes.fromhex(envelope.public_key))
    check = verify_envelope_signature(envelope, allow_legacy_v1=False)
    assert check.key_bound is True
    assert check.format_version == "2"


def test_p256_provider_end_to_end(model: Model) -> None:
    signer = SoftwareP256Signer()
    envelope = sign_with_provider(model.manifest, model.mbom, signer)

    assert envelope.signature_type == ALGORITHM_ECDSA_P256_SHA256
    check = verify_envelope_signature(envelope)
    assert check.algorithm == ALGORITHM_ECDSA_P256_SHA256
    assert check.key_fingerprint == key_fingerprint(signer.public_key())


def test_provider_exception_text_never_reaches_the_error(model: Model) -> None:
    class Leaky(SoftwareP256Signer):
        def sign(self, message: bytes) -> bytes:
            raise RuntimeError("AccessDenied for token SECRET-TOKEN-123 on arn:aws:kms:secret")

    with pytest.raises(SigningProviderError) as info:
        sign_with_provider(model.manifest, model.mbom, Leaky())
    assert "SECRET-TOKEN-123" not in str(info.value)
    assert "arn:aws" not in str(info.value)
    assert "RuntimeError" in str(info.value)
    assert info.value.__cause__ is None
    assert info.value.__suppress_context__ is True


def test_adapter_raised_provider_errors_pass_through_unchanged(model: Model) -> None:
    class Adapter(SoftwareP256Signer):
        def sign(self, message: bytes) -> bytes:
            raise SigningProviderError("KMS key is disabled; enable it and retry.")

    with pytest.raises(SigningProviderError, match="KMS key is disabled"):
        sign_with_provider(model.manifest, model.mbom, Adapter())


@pytest.mark.parametrize("bad", [b"", b"garbage" * 8, b"\x00" * 200, "not-bytes", None])
def test_unusable_or_invalid_signatures_are_refused(model: Model, bad: object) -> None:
    class Bad(SoftwareP256Signer):
        def sign(self, message: bytes) -> bytes:
            return bad  # type: ignore[return-value]

    with pytest.raises(SigningProviderError):
        sign_with_provider(model.manifest, model.mbom, Bad())


def test_signature_from_a_different_key_than_the_reported_public_key_is_refused(
    model: Model,
) -> None:
    """A KMS alias repointed at another key: signs fine, but not as the key it reports."""

    class Mismatched(SoftwareP256Signer):
        def __init__(self) -> None:
            super().__init__()
            self._other = SoftwareP256Signer()

        def sign(self, message: bytes) -> bytes:
            return self._other.sign(message)

    with pytest.raises(SigningProviderError, match="does not verify against its own"):
        sign_with_provider(model.manifest, model.mbom, Mismatched())


def test_unknown_algorithm_is_refused_before_signing(model: Model) -> None:
    calls: list[bytes] = []

    class Unknown(SoftwareP256Signer):
        @property
        def algorithm(self) -> str:
            return "rsa-pss-2048"

        def sign(self, message: bytes) -> bytes:
            calls.append(message)
            return super().sign(message)

    with pytest.raises(UnsupportedSignatureSchemeError):
        sign_with_provider(model.manifest, model.mbom, Unknown())
    assert calls == []


@pytest.mark.parametrize("bad_identity", ["", None])
def test_empty_identity_is_refused(model: Model, bad_identity: object) -> None:
    class NoName(SoftwareP256Signer):
        @property
        def identity(self) -> str:
            return bad_identity  # type: ignore[return-value]

    with pytest.raises(SigningProviderError):
        sign_with_provider(model.manifest, model.mbom, NoName())


def test_public_key_of_wrong_type_is_refused(model: Model) -> None:
    class NoKey(SoftwareP256Signer):
        def public_key(self) -> bytes:
            return None  # type: ignore[return-value]

    with pytest.raises(SigningProviderError):
        sign_with_provider(model.manifest, model.mbom, NoKey())


def test_local_signer_repr_contains_no_key_material() -> None:
    keypair = generate_keypair("dev@example.com")
    text = repr(LocalEd25519Signer(keypair))
    assert keypair.public_key.public_bytes_raw().hex() not in text
    assert "dev@example.com" in text
