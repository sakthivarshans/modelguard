"""Signing providers: where the private key lives.

A provider turns bytes into a signature. Local files, cloud KMS and
HSMs all fit behind the same small interface, and none of them changes
how a signature is *verified* (see ``modelguard.signing.schemes``).

Contract for implementers
-------------------------

* ``algorithm`` must be a registered scheme id.
* ``public_key()`` returns the canonical public key bytes for that
  scheme. It may perform I/O (a KMS call) and may fail; cache it if
  that is expensive. ModelGuard never trusts it blindly: every signature
  is verified against it before an envelope is returned.
* ``sign(message)`` signs exactly the bytes it is given. The private key
  must not leave the provider.
* Exceptions raised by a provider are converted to
  ``SigningProviderError`` using only the exception *type name*, because
  third-party error text can contain credentials or resource names.
  Adapters that want actionable messages raise ``SigningProviderError``
  themselves with text they know is safe.
* ``identity`` is the signer's *claimed* label. It is recorded in the
  signed payload but is not verified by anything; only the key is.
"""

from __future__ import annotations

from typing import Protocol

from modelguard.signing.keys import LocalKeyPair
from modelguard.signing.schemes import ALGORITHM_ED25519


class SignerProvider(Protocol):
    @property
    def algorithm(self) -> str: ...

    @property
    def identity(self) -> str: ...

    def public_key(self) -> bytes: ...

    def sign(self, message: bytes) -> bytes: ...


class LocalEd25519Signer:
    """Signs with an unencrypted local Ed25519 key (development use).

    See the warning in ``modelguard.signing.keys``: this is not a
    production key-management story.
    """

    def __init__(self, keypair: LocalKeyPair) -> None:
        self._keypair = keypair

    @property
    def algorithm(self) -> str:
        return ALGORITHM_ED25519

    @property
    def identity(self) -> str:
        return self._keypair.identity

    def public_key(self) -> bytes:
        return self._keypair.public_key.public_bytes_raw()

    def sign(self, message: bytes) -> bytes:
        return self._keypair.private_key.sign(message)

    def __repr__(self) -> str:
        # Never include key material.
        return f"LocalEd25519Signer(identity={self._keypair.identity!r})"
