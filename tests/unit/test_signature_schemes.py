"""Unit tests for scheme verifiers, the registry, and fingerprints."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from modelguard.exceptions import SignatureInvalidError, UnsupportedSignatureSchemeError
from modelguard.signing.schemes import (
    ALGORITHM_ECDSA_P256_SHA256,
    ALGORITHM_ED25519,
    DEFAULT_VERIFIERS,
    EcdsaP256Verifier,
    Ed25519Verifier,
    decode_hex_strict,
    key_fingerprint,
    verifier_registry,
)
from modelguard.signing.trust import public_key_fingerprint
from tests.signing_helpers import SoftwareP256Signer

MSG = b"canonical payload bytes"


def _ed25519() -> tuple[bytes, bytes]:
    key = Ed25519PrivateKey.generate()
    return key.public_key().public_bytes_raw(), key.sign(MSG)


def test_ed25519_round_trip() -> None:
    pub, sig = _ed25519()
    Ed25519Verifier().verify(pub, sig, MSG)


def test_ed25519_rejects_wrong_message_and_wrong_key() -> None:
    pub, sig = _ed25519()
    other_pub, _ = _ed25519()
    with pytest.raises(SignatureInvalidError):
        Ed25519Verifier().verify(pub, sig, b"different")
    with pytest.raises(SignatureInvalidError):
        Ed25519Verifier().verify(other_pub, sig, MSG)


@pytest.mark.parametrize("pub_len,sig_len", [(31, 64), (33, 64), (32, 63), (32, 65), (0, 0)])
def test_ed25519_rejects_wrong_lengths(pub_len: int, sig_len: int) -> None:
    with pytest.raises(SignatureInvalidError):
        Ed25519Verifier().verify(bytes(pub_len), bytes(sig_len), MSG)


def test_p256_round_trip() -> None:
    signer = SoftwareP256Signer()
    EcdsaP256Verifier().verify(signer.public_key(), signer.sign(MSG), MSG)


def test_p256_rejects_tampered_message_and_other_key() -> None:
    a, b = SoftwareP256Signer(), SoftwareP256Signer()
    sig = a.sign(MSG)
    with pytest.raises(SignatureInvalidError):
        EcdsaP256Verifier().verify(a.public_key(), sig, b"different")
    with pytest.raises(SignatureInvalidError):
        EcdsaP256Verifier().verify(b.public_key(), sig, MSG)


def test_p256_refuses_compressed_point() -> None:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    signer = SoftwareP256Signer()
    compressed = signer._key.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
    assert len(compressed) == 33
    with pytest.raises(SignatureInvalidError, match="uncompressed"):
        EcdsaP256Verifier().verify(compressed, signer.sign(MSG), MSG)


def test_p256_refuses_point_not_on_curve() -> None:
    signer = SoftwareP256Signer()
    off_curve = b"\x04" + b"\x01" * 64
    with pytest.raises(SignatureInvalidError):
        EcdsaP256Verifier().verify(off_curve, signer.sign(MSG), MSG)


@pytest.mark.parametrize("sig", [b"", b"\x30\x00", b"\x00" * 7, b"\x30" * 73, b"\xff" * 72])
def test_p256_refuses_malformed_signatures(sig: bytes) -> None:
    signer = SoftwareP256Signer()
    with pytest.raises(SignatureInvalidError):
        EcdsaP256Verifier().verify(signer.public_key(), sig, MSG)


def test_ed25519_fingerprint_matches_the_pre_0_7_definition() -> None:
    """Existing trust roots (SHA-256 of the raw key) must keep matching."""
    pub, _ = _ed25519()
    assert key_fingerprint(pub) == public_key_fingerprint(pub.hex())


def test_default_registry_is_immutable_and_has_both_schemes() -> None:
    assert set(DEFAULT_VERIFIERS) == {ALGORITHM_ED25519, ALGORITHM_ECDSA_P256_SHA256}
    with pytest.raises(TypeError):
        DEFAULT_VERIFIERS["evil"] = Ed25519Verifier()  # type: ignore[index]


def test_registry_cannot_replace_a_builtin_scheme() -> None:
    class Weak:
        algorithm = ALGORITHM_ED25519

        def verify(self, public_key: bytes, signature: bytes, message: bytes) -> None:
            return None  # would accept everything

    with pytest.raises(UnsupportedSignatureSchemeError, match="already registered"):
        verifier_registry([Weak()])


def test_registry_accepts_a_new_scheme_without_mutating_the_default() -> None:
    class Custom:
        algorithm = "custom-v1"

        def verify(self, public_key: bytes, signature: bytes, message: bytes) -> None:
            return None

    registry = verifier_registry([Custom()])
    assert "custom-v1" in registry
    assert "custom-v1" not in DEFAULT_VERIFIERS


@pytest.mark.parametrize(
    "value", ["AB", "a b", "abc", "zz", "0x00", " 00", "00\n"]
)
def test_strict_hex_refuses_non_canonical_spellings(value: str) -> None:
    with pytest.raises(SignatureInvalidError):
        decode_hex_strict(value, what="x", max_bytes=8)


def test_strict_hex_refuses_oversized_input_before_decoding() -> None:
    with pytest.raises(SignatureInvalidError, match="too long"):
        decode_hex_strict("00" * 1000, what="x", max_bytes=8)


def test_strict_hex_accepts_canonical() -> None:
    assert decode_hex_strict("00ff", what="x", max_bytes=8) == b"\x00\xff"
