"""KmsSignerProvider tested against a real moto KMS emulator (not a fake).

moto's ``mock_aws`` intercepts boto3 calls in-process and implements
real KMS request/response semantics (including validation errors for
wrong key types and missing keys), so these are genuine integration
tests of the adapter against KMS's actual API shape -- not mocks of
our own code.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

pytest.importorskip("boto3")
pytest.importorskip("moto")

import boto3
from moto import mock_aws

from modelguard.exceptions import SigningProviderError
from modelguard.signing.kms import MAX_KMS_RAW_MESSAGE_BYTES, KmsSignerProvider
from modelguard.signing.schemes import ALGORITHM_ECDSA_P256_SHA256, key_fingerprint
from modelguard.signing.signer import sign_with_provider
from modelguard.signing.verifier import verify_envelope_signature
from tests.signing_helpers import make_model


@pytest.fixture
def kms_client(monkeypatch: pytest.MonkeyPatch) -> Iterator[object]:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    with mock_aws():
        yield boto3.client("kms")


@pytest.fixture
def p256_key_id(kms_client: object) -> str:
    response = kms_client.create_key(KeySpec="ECC_NIST_P256", KeyUsage="SIGN_VERIFY")  # type: ignore[attr-defined]
    return str(response["KeyMetadata"]["KeyId"])


def test_end_to_end_sign_and_verify(kms_client: object, p256_key_id: str, tmp_path: Path) -> None:
    model = make_model(tmp_path)
    provider = KmsSignerProvider(p256_key_id, "ci@example.com", client=kms_client)
    envelope = sign_with_provider(model.manifest, model.mbom, provider)

    check = verify_envelope_signature(envelope)
    assert check.algorithm == ALGORITHM_ECDSA_P256_SHA256
    assert check.key_bound is True
    assert check.key_fingerprint == key_fingerprint(provider.public_key())


def test_public_key_is_cached_after_first_call(kms_client: object, p256_key_id: str) -> None:
    calls = {"n": 0}
    real_get_public_key = kms_client.get_public_key  # type: ignore[attr-defined]

    def counting_get_public_key(**kwargs: object) -> object:
        calls["n"] += 1
        return real_get_public_key(**kwargs)

    kms_client.get_public_key = counting_get_public_key  # type: ignore[attr-defined]
    provider = KmsSignerProvider(p256_key_id, "ci@example.com", client=kms_client)
    first = provider.public_key()
    second = provider.public_key()
    assert first == second
    assert calls["n"] == 1


def test_wrong_key_spec_is_refused(kms_client: object) -> None:
    rsa_key_id = kms_client.create_key(KeySpec="RSA_2048", KeyUsage="SIGN_VERIFY")["KeyMetadata"][  # type: ignore[attr-defined]
        "KeyId"
    ]
    provider = KmsSignerProvider(rsa_key_id, "ci@example.com", client=kms_client)
    with pytest.raises(SigningProviderError, match="RSA_2048"):
        provider.public_key()


def test_signing_with_a_wrong_key_usage_key_fails_closed(kms_client: object, tmp_path: Path) -> None:
    """A real KMS validation error (wrong KeyUsage for Sign), surfaced
    through sign_with_provider's exception-normalizing wrapper."""
    encrypt_key_id = kms_client.create_key(  # type: ignore[attr-defined]
        KeySpec="SYMMETRIC_DEFAULT", KeyUsage="ENCRYPT_DECRYPT"
    )["KeyMetadata"]["KeyId"]

    class BadUsageProvider(KmsSignerProvider):
        def public_key(self) -> bytes:
            # Bypass the key-spec check to reach the real Sign-time failure.
            return b"\x04" + b"\x01" * 64

    provider = BadUsageProvider(encrypt_key_id, "ci@example.com", client=kms_client)
    model = make_model(tmp_path)
    with pytest.raises(SigningProviderError):
        sign_with_provider(model.manifest, model.mbom, provider)


def test_nonexistent_key_fails_closed(kms_client: object) -> None:
    provider = KmsSignerProvider("alias/does-not-exist", "ci@example.com", client=kms_client)
    with pytest.raises(SigningProviderError):
        provider.public_key()


def test_oversized_message_is_refused_before_any_api_call(
    kms_client: object, p256_key_id: str
) -> None:
    calls = {"n": 0}
    real_sign = kms_client.sign  # type: ignore[attr-defined]

    def counting_sign(**kwargs: object) -> object:
        calls["n"] += 1
        return real_sign(**kwargs)

    kms_client.sign = counting_sign  # type: ignore[attr-defined]
    provider = KmsSignerProvider(p256_key_id, "ci@example.com", client=kms_client)
    with pytest.raises(SigningProviderError, match="4096"):
        provider.sign(b"x" * (MAX_KMS_RAW_MESSAGE_BYTES + 1))
    assert calls["n"] == 0


def test_boto3_exception_text_never_reaches_the_raised_error(
    kms_client: object, p256_key_id: str, tmp_path: Path
) -> None:
    class LeakySignProvider(KmsSignerProvider):
        def sign(self, message: bytes) -> bytes:
            raise RuntimeError(f"AccessDenied for key {p256_key_id} account 123456789012")

    provider = LeakySignProvider(p256_key_id, "ci@example.com", client=kms_client)
    model = make_model(tmp_path)
    with pytest.raises(SigningProviderError) as info:
        sign_with_provider(model.manifest, model.mbom, provider)
    assert p256_key_id not in str(info.value)
    assert "123456789012" not in str(info.value)


def test_repr_never_includes_the_client_or_credentials(kms_client: object, p256_key_id: str) -> None:
    provider = KmsSignerProvider(p256_key_id, "ci@example.com", client=kms_client)
    text = repr(provider)
    assert "testing" not in text  # the fake access key id
    assert "identity='ci@example.com'" in text


def test_missing_kms_extra_produces_a_clear_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """When boto3 truly isn't importable, construction (with no injected
    client) must fail with a clear message, not an ImportError traceback."""
    import builtins

    real_import = builtins.__import__

    def blocking_import(name: str, *args: object, **kwargs: object) -> object:
        if name == "boto3":
            raise ImportError("No module named 'boto3'")
        return real_import(name, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(builtins, "__import__", blocking_import)
    with pytest.raises(SigningProviderError, match="modelguard\\[kms\\]"):
        KmsSignerProvider("some-key-id", "ci@example.com")
