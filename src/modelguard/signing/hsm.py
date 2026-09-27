"""PKCS#11 (HSM) signing provider: a ``SignerProvider`` backed by a
PKCS#11 token -- a hardware security module, or a software token such
as SoftHSM2 used for this project's own tests.

Requires the optional dependency: ``pip install "modelguard[hsm]"``
(``python-pkcs11``). The core package never imports this module.

Supported today: EC P-256 (``secp256r1``) keys, matching
``modelguard.signing.schemes.ALGORITHM_ECDSA_P256_SHA256``.

SECURITY MODEL
---------------
* **The private key never leaves the token.** This provider only opens
  a PKCS#11 session and issues ``Sign`` / attribute-read calls.
* **Hashing happens on the host, not the token.** Most PKCS#11 tokens
  (SoftHSM2 included, confirmed empirically for this module) expose
  only the pure ``Mechanism.ECDSA`` operation -- signing an
  already-hashed digest -- not a combined "hash-then-sign" mechanism.
  This provider therefore computes SHA-256 of the message itself before
  calling ``Sign``, which is standard PKCS#11 ECDSA usage, not a
  shortcut, and matches exactly what
  ``modelguard.signing.schemes.EcdsaP256Verifier`` expects on the
  signing side (SHA-256 then ECDSA).
* **Wire-format conversion, both directions.** PKCS#11 returns a raw
  ECDSA signature as the concatenation ``r || s`` (each a fixed
  32-byte big-endian integer for P-256), not the DER
  ``ECDSA-Sig-Value`` ModelGuard's ``ecdsa-p256-sha256`` scheme expects
  on the wire; this provider converts with
  ``cryptography...encode_dss_signature`` before returning. Likewise
  the public key comes back as a DER ``OCTET STRING`` wrapping the raw
  SEC1 point (PKCS#11's ``CKA_EC_POINT`` encoding), which this provider
  unwraps to the bare uncompressed point the scheme expects.
* **The PIN is used only to open the session** and is never logged or
  included in any exception; every PKCS#11 failure (wrong PIN, missing
  token, missing key) is converted to ``SigningProviderError`` with only
  the exception type name.
"""

from __future__ import annotations

import hashlib
from typing import Any, Self

from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from modelguard.exceptions import SigningProviderError
from modelguard.signing.schemes import ALGORITHM_ECDSA_P256_SHA256

_EC_POINT_BYTES = 65  # uncompressed SEC1 point for P-256: 0x04 || X(32) || Y(32)
_RAW_SIGNATURE_BYTES = 64  # r(32) || s(32) for P-256


class Pkcs11SignerProvider:
    """``SignerProvider`` backed by a PKCS#11 EC P-256 key.

    ``library_path`` is the path to the PKCS#11 module (``.so``), e.g.
    ``/usr/lib/softhsm/libsofthsm2.so`` for SoftHSM2, or a vendor HSM's
    library in production. ``token_label`` selects the token;
    ``key_label`` selects the EC key pair on it (both the public and
    private key objects must share this label). The PIN opens a
    read-only session at construction time, so a wrong PIN or missing
    key fails immediately rather than at the first ``sign()`` call.

    Use as a context manager (or call ``close()``) to release the
    session when done; leaving it open is harmless but ties up a
    session slot on the token.
    """

    def __init__(
        self,
        library_path: str,
        token_label: str,
        key_label: str,
        user_pin: str,
        identity: str,
        *,
        lib: Any = None,
    ) -> None:
        if not identity:
            raise SigningProviderError("A signer identity is required.")
        self._identity = identity

        try:
            import pkcs11
        except ImportError as exc:
            raise SigningProviderError(
                'PKCS#11/HSM support requires the \'hsm\' extra: pip install "modelguard[hsm]".'
            ) from exc
        self._pkcs11 = pkcs11

        try:
            library = lib if lib is not None else pkcs11.lib(library_path)
            token = library.get_token(token_label=token_label)
            self._session = token.open(user_pin=user_pin, rw=False)
        except SigningProviderError:
            raise
        except Exception as exc:
            raise SigningProviderError(
                f"Could not open a PKCS#11 session ({type(exc).__name__})."
            ) from exc

        try:
            self._private_key: Any = self._session.get_key(
                label=key_label,
                object_class=pkcs11.ObjectClass.PRIVATE_KEY,
                key_type=pkcs11.KeyType.EC,
            )
            public_key = self._session.get_key(
                label=key_label,
                object_class=pkcs11.ObjectClass.PUBLIC_KEY,
                key_type=pkcs11.KeyType.EC,
            )
        except Exception as exc:
            self._session.close()
            raise SigningProviderError(
                f"Could not load PKCS#11 key {key_label!r} ({type(exc).__name__})."
            ) from exc

        self._public_key_cache = _decode_ec_point(public_key[pkcs11.Attribute.EC_POINT])

    @property
    def algorithm(self) -> str:
        return ALGORITHM_ECDSA_P256_SHA256

    @property
    def identity(self) -> str:
        return self._identity

    def public_key(self) -> bytes:
        return self._public_key_cache

    def sign(self, message: bytes) -> bytes:
        digest = hashlib.sha256(message).digest()
        try:
            raw_signature = self._private_key.sign(digest, mechanism=self._pkcs11.Mechanism.ECDSA)
        except SigningProviderError:
            raise
        except Exception as exc:  # noqa: BLE001 - any PKCS#11 failure must fail closed
            raise SigningProviderError(f"PKCS#11 Sign failed ({type(exc).__name__}).") from None
        if len(raw_signature) != _RAW_SIGNATURE_BYTES:
            raise SigningProviderError(
                f"PKCS#11 returned a {len(raw_signature)}-byte signature; expected "
                f"{_RAW_SIGNATURE_BYTES} (r || s for P-256)."
            )
        r = int.from_bytes(raw_signature[:32], "big")
        s = int.from_bytes(raw_signature[32:], "big")
        return encode_dss_signature(r, s)

    def close(self) -> None:
        """Close the PKCS#11 session. Safe to call more than once."""
        try:
            self._session.close()
        except Exception:  # noqa: BLE001, S110 - best-effort cleanup on close(); nothing more to do
            pass

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def __repr__(self) -> str:
        # Never include the PIN or anything session-related.
        return f"Pkcs11SignerProvider(identity={self._identity!r})"


def _decode_ec_point(der_octet_string: bytes) -> bytes:
    """Unwrap PKCS#11's ``CKA_EC_POINT`` (a DER ``OCTET STRING``) to the
    raw uncompressed SEC1 point ModelGuard's scheme expects.
    """
    try:
        import asn1crypto.core as asn1_core
    except ImportError as exc:
        raise SigningProviderError(
            'PKCS#11/HSM support requires the \'hsm\' extra: pip install "modelguard[hsm]".'
        ) from exc
    try:
        raw_point: bytes = asn1_core.OctetString.load(der_octet_string).native
    except Exception as exc:
        raise SigningProviderError(f"Malformed PKCS#11 EC_POINT attribute ({type(exc).__name__}).") from exc
    if len(raw_point) != _EC_POINT_BYTES or raw_point[0] != 0x04:
        raise SigningProviderError(
            "PKCS#11 key's EC_POINT is not a 65-byte uncompressed P-256 point."
        )
    return bytes(raw_point)


def generate_ec_keypair(session: Any, label: str, key_id: bytes) -> None:
    """Generate and store a P-256 key pair on ``session``'s token.

    A provisioning helper, not part of ``SignerProvider`` -- takes a
    caller-supplied read-write session (this module never opens one
    itself, since ``Pkcs11SignerProvider`` only ever needs to read and
    sign). Used to bootstrap a token in tests and for operators setting
    up a new HSM-backed key outside of any existing tooling their HSM
    vendor provides.
    """
    try:
        import pkcs11
        from pkcs11.util.ec import encode_named_curve_parameters
    except ImportError as exc:
        raise SigningProviderError(
            'PKCS#11/HSM support requires the \'hsm\' extra: pip install "modelguard[hsm]".'
        ) from exc
    params = encode_named_curve_parameters("secp256r1")
    session.generate_keypair(
        pkcs11.KeyType.EC,
        public_template={pkcs11.Attribute.EC_PARAMS: params},
        label=label,
        id=key_id,
        store=True,
    )
