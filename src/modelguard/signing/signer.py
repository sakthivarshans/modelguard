"""Signing of a ModelGuard signature payload.

``sign_with_provider`` is the single place an envelope is produced.
It writes a format-version-2 payload (committing to the algorithm and
the key id), asks the provider to sign the canonical payload bytes, and
then **verifies the result before returning it**. A provider that
returns garbage, or whose public key does not correspond to the key it
signs with, therefore fails loudly here instead of producing a
signature file that only fails later at some deployment gate.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import TypeVar

from modelguard.exceptions import (
    ModelGuardError,
    SigningProviderError,
    UnsupportedSignatureSchemeError,
)
from modelguard.manifest.models import Manifest
from modelguard.mbom.models import MLBOM
from modelguard.signing.envelope import SCHEMA_VERSION_BOUND, SignatureEnvelope, SignaturePayload
from modelguard.signing.keys import LocalKeyPair
from modelguard.signing.providers import LocalEd25519Signer, SignerProvider
from modelguard.signing.schemes import (
    DEFAULT_VERIFIERS,
    MAX_KEY_BYTES,
    MAX_SIGNATURE_BYTES,
    SignatureVerifier,
    key_fingerprint,
)
from modelguard.signing.verifier import verify_envelope_signature

_T = TypeVar("_T")


def sign_with_provider(
    manifest: Manifest,
    mbom: MLBOM,
    provider: SignerProvider,
    verifiers: Mapping[str, SignatureVerifier] = DEFAULT_VERIFIERS,
) -> SignatureEnvelope:
    """Sign a manifest + ML-BOM pair with any ``SignerProvider``.

    The payload binds the artifact digest, the ML-BOM digest, declared
    model identity, the claimed signer identity, the signing time, the
    algorithm, and the fingerprint of the signing key.

    Fails closed with ``SigningProviderError`` if the provider raises,
    returns unusable bytes, or returns a signature that does not verify
    against its own reported public key; with
    ``UnsupportedSignatureSchemeError`` if the provider's algorithm is
    not one this process can also verify (nothing is signed then).
    """
    algorithm = _provider_call(lambda: provider.algorithm)
    if not isinstance(algorithm, str) or algorithm not in verifiers:
        raise UnsupportedSignatureSchemeError(
            f"Refusing to sign with algorithm {algorithm!r}: it is not a registered scheme "
            "this process can verify."
        )

    identity = _provider_call(lambda: provider.identity)
    public_key = _provider_call(provider.public_key)
    if not isinstance(identity, str) or not identity:
        raise SigningProviderError("The signing provider returned an empty or invalid identity.")
    if not isinstance(public_key, bytes) or not 0 < len(public_key) <= MAX_KEY_BYTES:
        raise SigningProviderError("The signing provider returned an unusable public key.")

    mbom_digest = hashlib.sha256(mbom.canonical_json()).hexdigest()
    payload = SignaturePayload(
        schema_version=SCHEMA_VERSION_BOUND,
        artifact_digest=f"{manifest.algorithm}:{manifest.digest}",
        mbom_digest=f"sha256:{mbom_digest}",
        model_id=manifest.model_id,
        version=manifest.version,
        signer_identity=identity,
        signed_at=datetime.now(UTC).isoformat(),
        signature_algorithm=algorithm,
        key_id=key_fingerprint(public_key),
    )

    signature = _provider_call(lambda: provider.sign(payload.canonical_json()))
    if not isinstance(signature, bytes) or not 0 < len(signature) <= MAX_SIGNATURE_BYTES:
        raise SigningProviderError("The signing provider returned an unusable signature.")

    envelope = SignatureEnvelope(
        signature_type=algorithm,
        payload=payload,
        signature=signature.hex(),
        public_key=public_key.hex(),
    )

    try:
        verify_envelope_signature(envelope, verifiers, allow_legacy_v1=False)
    except ModelGuardError as exc:
        raise SigningProviderError(
            "The signing provider returned a signature that does not verify against its own "
            "public key, so no envelope was produced. The provider may be misconfigured (for "
            "example a key alias that now points at a different key)."
        ) from exc
    return envelope


def sign_artifact(manifest: Manifest, mbom: MLBOM, keypair: LocalKeyPair) -> SignatureEnvelope:
    """Sign a manifest + ML-BOM pair with a local Ed25519 keypair.

    Convenience wrapper over ``sign_with_provider`` (Phase 1 API).
    Since 0.7.0 the envelope is format version 2; see
    ``modelguard.signing.envelope``.
    """
    return sign_with_provider(manifest, mbom, LocalEd25519Signer(keypair))


def _provider_call(call: Callable[[], _T]) -> _T:
    """Run a provider method, converting foreign exceptions into a safe error.

    Only the exception *type* is reported. Provider error text can carry
    credentials, key ARNs, or PINs, and the chained cause is dropped for
    the same reason (tracebacks print causes).
    """
    try:
        return call()
    except ModelGuardError:
        raise
    except Exception as exc:  # noqa: BLE001 -- any provider fault must fail closed
        raise SigningProviderError(
            f"The signing provider failed ({type(exc).__name__}); no signature was produced."
        ) from None
