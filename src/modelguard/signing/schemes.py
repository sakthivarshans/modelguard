"""Signature schemes: algorithm identifiers, wire formats, verifiers.

A *scheme* fully determines how a signature is checked: the algorithm,
the hash, and the byte encodings of the public key and the signature.
Verification depends only on (scheme, public key, signature, message).
Where the private key lives -- a local file, a KMS, an HSM -- is a
signing-side concern (see ``modelguard.signing.providers``) and never
changes how a signature is verified.

Registered schemes
------------------

``ed25519``
    Public key: the 32 raw bytes. Signature: the 64 raw bytes.
    Message: signed as-is (Ed25519 hashes internally).

``ecdsa-p256-sha256``
    Public key: the 65-byte uncompressed SEC1 point (``0x04 || X || Y``).
    Compressed points are refused. Signature: ASN.1 DER ``ECDSA-Sig-Value``
    (what AWS KMS and OpenSSL emit). Message: hashed with SHA-256 by the
    scheme. Signature bytes are **not unique** (``(r, s)`` and
    ``(r, n - s)`` both verify), so a signature must never be used as an
    identifier -- identity is the artifact digest.

Security rules for this module
------------------------------

* The scheme used to verify comes from a registry the *caller*
  controls, keyed by an identifier that the signed payload commits to.
  It is never inferred from the shape of an attacker-supplied key.
* An identifier that is not in the registry fails closed
  (``UnsupportedSignatureSchemeError``).
* Every length and encoding is checked before any cryptographic call,
  so hostile sizes cost nothing and produce a precise error.
* The module-level default registry is an immutable mapping; there is
  no global registration API.

Known limitation: Ed25519 verification is delegated to the
``cryptography`` package (OpenSSL). It does not reject small-order
public keys, so a *universal* signature under such a key verifies for
any message without any private key. Trust roots are the control that
makes this harmless: no honest deployment lists such a key. See
``docs/limitations.md``.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping
from types import MappingProxyType
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from modelguard.exceptions import SignatureInvalidError, UnsupportedSignatureSchemeError

ALGORITHM_ED25519 = "ed25519"
ALGORITHM_ECDSA_P256_SHA256 = "ecdsa-p256-sha256"

ED25519_PUBLIC_KEY_LEN = 32
ED25519_SIGNATURE_LEN = 64
P256_PUBLIC_KEY_LEN = 65
# DER ECDSA-Sig-Value for P-256: at least 8 bytes (two 1-byte integers),
# at most 72 (two 33-byte integers with leading zero, plus framing).
P256_MIN_SIGNATURE_LEN = 8
P256_MAX_SIGNATURE_LEN = 72

# Upper bound for any decoded public key or signature, across schemes.
MAX_KEY_BYTES = 128
MAX_SIGNATURE_BYTES = 128

_LOWER_HEX = re.compile(r"[0-9a-f]*")


class SignatureVerifier(Protocol):
    """Checks one signature scheme.

    Implementations must raise ``SignatureInvalidError`` for *any*
    failure -- bad encoding, wrong length, wrong key, wrong message --
    and return ``None`` only when the signature is valid.
    """

    @property
    def algorithm(self) -> str: ...

    def verify(self, public_key: bytes, signature: bytes, message: bytes) -> None: ...


class Ed25519Verifier:
    """Verifier for ``ed25519``."""

    @property
    def algorithm(self) -> str:
        return ALGORITHM_ED25519

    def verify(self, public_key: bytes, signature: bytes, message: bytes) -> None:
        if len(public_key) != ED25519_PUBLIC_KEY_LEN:
            raise SignatureInvalidError(
                f"An ed25519 public key must be {ED25519_PUBLIC_KEY_LEN} bytes, "
                f"got {len(public_key)}."
            )
        if len(signature) != ED25519_SIGNATURE_LEN:
            raise SignatureInvalidError(
                f"An ed25519 signature must be {ED25519_SIGNATURE_LEN} bytes, "
                f"got {len(signature)}."
            )
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        except InvalidSignature:
            raise SignatureInvalidError(_MISMATCH_MESSAGE) from None
        except ValueError as exc:
            raise SignatureInvalidError(f"Malformed ed25519 key or signature: {exc}") from exc


class EcdsaP256Verifier:
    """Verifier for ``ecdsa-p256-sha256``."""

    @property
    def algorithm(self) -> str:
        return ALGORITHM_ECDSA_P256_SHA256

    def verify(self, public_key: bytes, signature: bytes, message: bytes) -> None:
        if len(public_key) != P256_PUBLIC_KEY_LEN or public_key[0] != 0x04:
            raise SignatureInvalidError(
                "An ecdsa-p256-sha256 public key must be an uncompressed SEC1 point "
                f"({P256_PUBLIC_KEY_LEN} bytes starting with 0x04); compressed and "
                "other encodings are refused."
            )
        if not P256_MIN_SIGNATURE_LEN <= len(signature) <= P256_MAX_SIGNATURE_LEN:
            raise SignatureInvalidError(
                "An ecdsa-p256-sha256 signature must be a DER ECDSA-Sig-Value of "
                f"{P256_MIN_SIGNATURE_LEN}-{P256_MAX_SIGNATURE_LEN} bytes, got {len(signature)}."
            )
        try:
            key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key)
            key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            raise SignatureInvalidError(_MISMATCH_MESSAGE) from None
        except ValueError as exc:
            # from_encoded_point raises ValueError for a point that is not on the curve.
            raise SignatureInvalidError(f"Malformed ecdsa-p256 key or signature: {exc}") from exc


_MISMATCH_MESSAGE = (
    "Signature does not match the signed payload. The payload or signature bytes may "
    "have been altered, or the wrong public key was supplied."
)


def _build_default_registry() -> Mapping[str, SignatureVerifier]:
    verifiers: tuple[SignatureVerifier, ...] = (Ed25519Verifier(), EcdsaP256Verifier())
    return MappingProxyType({v.algorithm: v for v in verifiers})


DEFAULT_VERIFIERS: Mapping[str, SignatureVerifier] = _build_default_registry()


def verifier_registry(extra: Iterable[SignatureVerifier] = ()) -> Mapping[str, SignatureVerifier]:
    """Return an immutable registry: the built-in schemes plus ``extra``.

    Refuses to let ``extra`` replace a built-in scheme or to contain two
    verifiers for one algorithm; silently swapping the implementation
    behind ``ed25519`` is exactly what an attacker with a plugin hook
    would want.
    """
    registry: dict[str, SignatureVerifier] = dict(DEFAULT_VERIFIERS)
    for verifier in extra:
        if verifier.algorithm in registry:
            raise UnsupportedSignatureSchemeError(
                f"A verifier for {verifier.algorithm!r} is already registered; "
                "built-in and duplicate schemes cannot be replaced."
            )
        registry[verifier.algorithm] = verifier
    return MappingProxyType(registry)


def key_fingerprint(public_key: bytes) -> str:
    """SHA-256 (lowercase hex) of the canonical public key bytes.

    For Ed25519 this is identical to the fingerprint ModelGuard has
    always used (SHA-256 of the raw 32-byte key), so existing trust
    roots keep working.
    """
    return hashlib.sha256(public_key).hexdigest()


def decode_hex_strict(value: str, *, what: str, max_bytes: int) -> bytes:
    """Decode canonical lowercase hex, refusing everything else.

    ``bytes.fromhex`` tolerates embedded whitespace and upper case, so
    two different strings could name the same key. Evidence should have
    one spelling.
    """
    if len(value) > 2 * max_bytes:
        raise SignatureInvalidError(f"{what} is too long ({len(value)} hex characters).")
    if len(value) % 2 != 0 or not _LOWER_HEX.fullmatch(value):
        raise SignatureInvalidError(f"{what} is not canonical lowercase hexadecimal.")
    return bytes.fromhex(value)
