"""AWS KMS signing provider: a ``SignerProvider`` backed by an asymmetric
KMS key.

Requires the optional dependency: ``pip install "modelguard[kms]"``.
The core package never imports this module; nothing here runs unless a
caller explicitly constructs ``KmsSignerProvider``.

Supported today: ``ECC_NIST_P256`` KMS keys with ``KeyUsage=SIGN_VERIFY``,
signing algorithm ``ECDSA_SHA_256`` -- exactly
``modelguard.signing.schemes.ALGORITHM_ECDSA_P256_SHA256``. AWS KMS does
not offer Ed25519 asymmetric keys as of this writing, so there is
nothing to adapt for that scheme.

SECURITY MODEL
---------------
* **The private key never leaves KMS.** This provider only ever calls
  ``GetPublicKey`` and ``Sign``; it holds no key material and cannot
  export any.
* **``MessageType="RAW"``, never ``"DIGEST"``.** Empirically, a
  ``DIGEST``-mode signature produced by the ``moto`` KMS test double did
  not verify against either the raw message or its SHA-256 digest under
  ``cryptography``'s ECDSA+SHA256 verifier, even though KMS's own
  ``Verify`` call reported it valid -- so ``Verify`` is not trusted here
  as ground truth on its own. ``RAW`` mode is unambiguous: real AWS KMS
  hashes the message with SHA-256 before signing in `RAW` mode, which is
  exactly what ``cryptography``'s ``ec.ECDSA(hashes.SHA256())`` verifies,
  and this was confirmed empirically against a real ``cryptography``
  verification, not against KMS's self-reported result.
* **The 4096-byte message limit is checked before calling KMS**, with a
  clear error, rather than surfacing KMS's own validation error. This
  is a documented, service-enforced limit of the ``Sign`` API's
  ``Message`` parameter for ``MessageType=RAW``, not a limit invented by
  this module. ModelGuard's signed payloads are on the order of a few
  hundred bytes, so this should never be reached in normal use.
* **Every KMS API failure fails closed.** Both ``public_key()`` and
  ``sign()`` catch any exception from the underlying boto3 call and
  raise ``SigningProviderError`` carrying only the exception type name
  -- never boto3's message text, which can carry account IDs, key ARNs,
  or other identifiers. This holds whether the provider is called
  directly or through ``sign_with_provider`` (which applies the same
  normalization again at its own layer, redundantly but harmlessly, for
  every ``SignerProvider`` implementation).
* **No local check of the KMS key's enabled/disabled status.** KMS
  itself is the authority on that, and a real KMS `Sign` call enforces
  it; this module does not duplicate that check. (The `moto` test
  double used for this project's tests does *not* enforce it -- see
  ``docs/limitations.md`` for what that means for test coverage of this
  specific behavior.) Independently, ``sign_with_provider`` always
  re-verifies the signature it produces against the key's own reported
  public key before returning an envelope, so an unexpectedly-successful
  call against a key that should have been unusable would still be
  caught if the result somehow didn't verify.
"""

from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key

from modelguard.exceptions import SigningProviderError
from modelguard.signing.schemes import ALGORITHM_ECDSA_P256_SHA256

# The Sign API's Message parameter for MessageType=RAW is capped at 4096
# bytes by AWS KMS itself (documented on the Sign/Verify API reference).
MAX_KMS_RAW_MESSAGE_BYTES = 4096

_EXPECTED_KEY_SPEC = "ECC_NIST_P256"
_SIGNING_ALGORITHM = "ECDSA_SHA_256"


class KmsSignerProvider:
    """``SignerProvider`` that signs with an AWS KMS asymmetric P-256 key.

    ``key_id`` is any KMS key identifier accepted by the ``Sign`` and
    ``GetPublicKey`` APIs (key ID, key ARN, alias name, or alias ARN).
    ``identity`` is the claimed signer identity recorded in the signed
    payload (see ``SignerProvider`` -- it is never itself verified).

    Pass ``client`` to inject a pre-built boto3 KMS client (a ``moto``
    mock in tests, or one configured with a specific profile/region in
    production); otherwise a default client is created from boto3's
    standard credential chain via ``boto3.client("kms", ...)``.
    """

    def __init__(
        self,
        key_id: str,
        identity: str,
        *,
        client: Any = None,
        region_name: str | None = None,
    ) -> None:
        if not key_id:
            raise SigningProviderError("A KMS key_id is required.")
        if not identity:
            raise SigningProviderError("A signer identity is required.")
        self._key_id = key_id
        self._identity = identity
        if client is not None:
            self._client = client
        else:
            try:
                import boto3
            except ImportError as exc:
                raise SigningProviderError(
                    "AWS KMS support requires the 'kms' extra: "
                    'pip install "modelguard[kms]".'
                ) from exc
            self._client = boto3.client("kms", region_name=region_name)
        self._public_key_cache: bytes | None = None

    @property
    def algorithm(self) -> str:
        return ALGORITHM_ECDSA_P256_SHA256

    @property
    def identity(self) -> str:
        return self._identity

    def public_key(self) -> bytes:
        """Fetch (and cache) the key's public point as an uncompressed SEC1 point.

        Raises ``SigningProviderError`` for any failure -- an unusable
        key spec, or the underlying KMS call itself failing (wrong
        permissions, key not found, network error) -- with only the
        exception type name, never boto3's message text. This holds
        whether called directly or through ``sign_with_provider``.
        """
        if self._public_key_cache is not None:
            return self._public_key_cache

        try:
            response = self._client.get_public_key(KeyId=self._key_id)
        except SigningProviderError:
            raise
        except Exception as exc:  # noqa: BLE001 - any KMS failure must fail closed
            raise SigningProviderError(
                f"KMS GetPublicKey failed ({type(exc).__name__})."
            ) from None

        key_spec = response.get("KeySpec") or response.get("CustomerMasterKeySpec")
        if key_spec != _EXPECTED_KEY_SPEC:
            raise SigningProviderError(
                f"KMS key {self._key_id!r} is a {key_spec!r} key; this adapter only supports "
                f"{_EXPECTED_KEY_SPEC!r} ({ALGORITHM_ECDSA_P256_SHA256})."
            )
        public_key = load_der_public_key(response["PublicKey"])
        if not isinstance(public_key, EllipticCurvePublicKey):
            raise SigningProviderError(
                f"KMS key {self._key_id!r} did not return an elliptic-curve public key."
            )
        self._public_key_cache = public_key.public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        )
        return self._public_key_cache

    def sign(self, message: bytes) -> bytes:
        """Sign ``message`` via KMS ``Sign`` with ``MessageType=RAW``.

        Raises ``SigningProviderError`` if ``message`` exceeds the KMS
        ``RAW``-mode limit (checked locally before any API call) or if
        the underlying KMS call fails, with only the exception type
        name. This holds whether called directly or through
        ``sign_with_provider``.
        """
        if len(message) > MAX_KMS_RAW_MESSAGE_BYTES:
            raise SigningProviderError(
                f"Message is {len(message)} bytes, exceeding the {MAX_KMS_RAW_MESSAGE_BYTES}-byte "
                "limit AWS KMS enforces for Sign with MessageType=RAW."
            )
        try:
            response = self._client.sign(
                KeyId=self._key_id,
                Message=message,
                MessageType="RAW",
                SigningAlgorithm=_SIGNING_ALGORITHM,
            )
        except SigningProviderError:
            raise
        except Exception as exc:  # noqa: BLE001 - any KMS failure must fail closed
            raise SigningProviderError(f"KMS Sign failed ({type(exc).__name__}).") from None
        return bytes(response["Signature"])

    def __repr__(self) -> str:
        # Never include anything from the client (credentials, region config).
        return f"KmsSignerProvider(key_id={self._key_id!r}, identity={self._identity!r})"
