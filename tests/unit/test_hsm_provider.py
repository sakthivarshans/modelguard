"""Pkcs11SignerProvider tested against a real SoftHSM2 token.

Not a fake: SoftHSM2 is a real, standards-compliant PKCS#11
implementation (software-backed rather than hardware-backed), and this
module drives it through the same `python-pkcs11` library and the same
call sequence a real HSM would see. If ``softhsm2-util`` or
``libsofthsm2.so`` are unavailable, these tests are skipped (visibly,
via ``pytest.skip``) rather than faked.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

pytest.importorskip("pkcs11")

from modelguard.exceptions import SigningProviderError
from modelguard.signing.hsm import Pkcs11SignerProvider, generate_ec_keypair
from modelguard.signing.schemes import ALGORITHM_ECDSA_P256_SHA256, key_fingerprint
from modelguard.signing.signer import sign_with_provider
from modelguard.signing.verifier import verify_envelope_signature
from tests.signing_helpers import make_model

SOFTHSM_LIB = "/usr/lib/softhsm/libsofthsm2.so"
TEST_PIN = "1234"
TEST_SO_PIN = "5678"
TOKEN_LABEL = "modelguard-test-session"

pytestmark = pytest.mark.skipif(
    shutil.which("softhsm2-util") is None or not Path(SOFTHSM_LIB).exists(),
    reason="softhsm2-util or libsofthsm2.so not installed in this environment",
)


@pytest.fixture(scope="session")
def softhsm_token(tmp_path_factory: pytest.TempPathFactory) -> str:
    """Initialize one real SoftHSM2 token for the whole test session,
    via the actual softhsm2-util CLI -- not a mock of it."""
    token_dir = tmp_path_factory.mktemp("softhsm_tokens")
    conf_path = tmp_path_factory.mktemp("softhsm_conf") / "softhsm2.conf"
    conf_path.write_text(
        f"directories.tokendir = {token_dir}\nobjectstore.backend = file\nlog.level = INFO\n"
    )
    os.environ["SOFTHSM2_CONF"] = str(conf_path)
    result = subprocess.run(
        [
            "softhsm2-util",
            "--init-token",
            "--free",
            "--label",
            TOKEN_LABEL,
            "--pin",
            TEST_PIN,
            "--so-pin",
            TEST_SO_PIN,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert "initialized" in result.stdout.lower()
    return TOKEN_LABEL


@pytest.fixture
def hsm_key_label(softhsm_token: str) -> Iterator[str]:
    """A fresh EC P-256 key pair, generated on the real token for this test."""
    import pkcs11

    label = f"test-key-{uuid.uuid4().hex[:12]}"
    lib = pkcs11.lib(SOFTHSM_LIB)
    token = lib.get_token(token_label=softhsm_token)
    with token.open(user_pin=TEST_PIN, rw=True) as session:
        generate_ec_keypair(session, label, label.encode())
    yield label


def test_end_to_end_sign_and_verify(
    softhsm_token: str, hsm_key_label: str, tmp_path: Path
) -> None:
    model = make_model(tmp_path)
    with Pkcs11SignerProvider(
        SOFTHSM_LIB, softhsm_token, hsm_key_label, TEST_PIN, "hsm@example.com"
    ) as provider:
        envelope = sign_with_provider(model.manifest, model.mbom, provider)
        check = verify_envelope_signature(envelope)
        assert check.algorithm == ALGORITHM_ECDSA_P256_SHA256
        assert check.key_bound is True
        assert check.key_fingerprint == key_fingerprint(provider.public_key())


def test_public_key_is_a_valid_uncompressed_p256_point(
    softhsm_token: str, hsm_key_label: str
) -> None:
    with Pkcs11SignerProvider(
        SOFTHSM_LIB, softhsm_token, hsm_key_label, TEST_PIN, "hsm@example.com"
    ) as provider:
        pub = provider.public_key()
        assert len(pub) == 65
        assert pub[0] == 0x04


def test_two_signatures_from_the_same_key_both_verify_independently(
    softhsm_token: str, hsm_key_label: str, tmp_path: Path
) -> None:
    model_a = make_model(tmp_path / "a")
    model_b = make_model(tmp_path / "b")
    with Pkcs11SignerProvider(
        SOFTHSM_LIB, softhsm_token, hsm_key_label, TEST_PIN, "hsm@example.com"
    ) as provider:
        env_a = sign_with_provider(model_a.manifest, model_a.mbom, provider)
        env_b = sign_with_provider(model_b.manifest, model_b.mbom, provider)
    verify_envelope_signature(env_a)
    verify_envelope_signature(env_b)
    assert env_a.public_key == env_b.public_key  # same signing key
    assert env_a.signature != env_b.signature  # different payloads


def test_wrong_pin_fails_closed(softhsm_token: str, hsm_key_label: str) -> None:
    with pytest.raises(SigningProviderError, match="session"):
        Pkcs11SignerProvider(SOFTHSM_LIB, softhsm_token, hsm_key_label, "0000", "hsm@example.com")


def test_missing_key_label_fails_closed(softhsm_token: str) -> None:
    with pytest.raises(SigningProviderError, match="key"):
        Pkcs11SignerProvider(
            SOFTHSM_LIB, softhsm_token, "no-such-key-label", TEST_PIN, "hsm@example.com"
        )


def test_missing_token_fails_closed() -> None:
    with pytest.raises(SigningProviderError, match="session"):
        Pkcs11SignerProvider(
            SOFTHSM_LIB, "no-such-token-label", "any-key", TEST_PIN, "hsm@example.com"
        )


def test_empty_identity_is_refused(softhsm_token: str, hsm_key_label: str) -> None:
    with pytest.raises(SigningProviderError, match="identity"):
        Pkcs11SignerProvider(SOFTHSM_LIB, softhsm_token, hsm_key_label, TEST_PIN, "")


def test_close_is_idempotent(softhsm_token: str, hsm_key_label: str) -> None:
    provider = Pkcs11SignerProvider(
        SOFTHSM_LIB, softhsm_token, hsm_key_label, TEST_PIN, "hsm@example.com"
    )
    provider.close()
    provider.close()  # must not raise


def test_repr_never_includes_the_pin(softhsm_token: str, hsm_key_label: str) -> None:
    with Pkcs11SignerProvider(
        SOFTHSM_LIB, softhsm_token, hsm_key_label, TEST_PIN, "hsm@example.com"
    ) as provider:
        text = repr(provider)
        assert TEST_PIN not in text
        assert "identity='hsm@example.com'" in text


def test_wrong_length_raw_signature_is_refused(softhsm_token: str, hsm_key_label: str) -> None:
    """SoftHSM2 always returns a correctly-shaped 64-byte r||s signature
    for P-256, so this guard has no natural trigger through the real
    token; substitute the private-key handle to force a malformed
    length and confirm the check itself actually runs."""
    with Pkcs11SignerProvider(
        SOFTHSM_LIB, softhsm_token, hsm_key_label, TEST_PIN, "hsm@example.com"
    ) as provider:

        class BadLengthKey:
            def sign(self, digest: bytes, mechanism: object) -> bytes:
                return b"\x00" * 63  # one byte short of the required 64

        provider._private_key = BadLengthKey()  # type: ignore[assignment]
        with pytest.raises(SigningProviderError, match="63-byte"):
            provider.sign(b"anything")


def test_missing_hsm_extra_produces_a_clear_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """When python-pkcs11 truly isn't importable, construction must fail
    with a clear message, not an ImportError traceback."""
    import builtins

    real_import = builtins.__import__

    def blocking_import(name: str, *args: object, **kwargs: object) -> object:
        if name == "pkcs11":
            raise ImportError("No module named 'pkcs11'")
        return real_import(name, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(builtins, "__import__", blocking_import)
    with pytest.raises(SigningProviderError, match="modelguard\\[hsm\\]"):
        Pkcs11SignerProvider(SOFTHSM_LIB, "t", "k", "1234", "id@example.com")
