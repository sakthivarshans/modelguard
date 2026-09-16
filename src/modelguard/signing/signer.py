"""Ed25519 signing of a ModelGuard signature payload."""

from __future__ import annotations

from datetime import UTC, datetime

from modelguard.manifest.models import Manifest
from modelguard.mbom.models import MLBOM
from modelguard.signing.envelope import SignatureEnvelope, SignaturePayload
from modelguard.signing.keys import LocalKeyPair


def sign_artifact(manifest: Manifest, mbom: MLBOM, keypair: LocalKeyPair) -> SignatureEnvelope:
    """Sign a manifest + ML-BOM pair with a local Ed25519 keypair.

    The signature covers a payload that binds together the artifact
    digest, the ML-BOM digest, declared model identity, the signer's
    claimed identity, and the signing time -- not the manifest or
    ML-BOM files themselves, so the payload stays small and its
    contents are exactly what ``verify_artifact`` re-checks.
    """
    import hashlib

    mbom_digest = hashlib.sha256(mbom.canonical_json()).hexdigest()

    payload = SignaturePayload(
        artifact_digest=f"{manifest.algorithm}:{manifest.digest}",
        mbom_digest=f"sha256:{mbom_digest}",
        model_id=manifest.model_id,
        version=manifest.version,
        signer_identity=keypair.identity,
        signed_at=datetime.now(UTC).isoformat(),
    )

    signature_bytes = keypair.private_key.sign(payload.canonical_json())
    public_key_bytes = keypair.public_key.public_bytes_raw()

    return SignatureEnvelope(
        payload=payload,
        signature=signature_bytes.hex(),
        public_key=public_key_bytes.hex(),
    )
