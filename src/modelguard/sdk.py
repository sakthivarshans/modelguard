"""High-level ``ModelGuard`` SDK facade.

This module implements the beginner-friendly API:

    from modelguard import ModelGuard

    guard = ModelGuard()
    result = guard.verify("./models/my-model", public_key_path="key.modelguard.pub")
    result.raise_if_denied()

Advanced users should import from the submodules directly
(``modelguard.hashing``, ``modelguard.mbom``, ``modelguard.signing``)
rather than through this facade.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from modelguard.exceptions import ModelGuardError, VerificationDenied
from modelguard.hashing.digest import ArtifactDigest, hash_artifact
from modelguard.manifest.builder import DeclaredMetadata, build_manifest
from modelguard.manifest.models import Manifest
from modelguard.mbom.generator import DeclaredProvenance, generate_mbom
from modelguard.mbom.models import MLBOM
from modelguard.provenance.graph import (
    children,
    find_deployments_using_revoked_model,
    find_models_derived_from,
    lineage,
    parents,
)
from modelguard.provenance.models import ProvenanceEvent, RelationshipType
from modelguard.provenance.store import LocalProvenanceStore
from modelguard.registry.local import LocalRegistry
from modelguard.registry.models import RegistryRecord, RevocationRecord
from modelguard.signing.envelope import SignatureEnvelope
from modelguard.signing.keys import LocalKeyPair, load_public_key
from modelguard.signing.signer import sign_artifact
from modelguard.signing.verifier import (
    check_artifact_digest,
    check_mbom_digest,
    check_signature_bytes,
)


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """Structured outcome of ``ModelGuard.verify()``.

    ``allowed`` reflects Phase 1's scope only: valid signature + digest
    match against the supplied public key and ML-BOM. It does not yet
    reflect policy evaluation, revocation, or scanning -- those are
    added in later phases and will be additional fields here, not a
    change to this field's meaning.
    """

    allowed: bool
    artifact_digest: str
    signature_valid: bool
    mbom_valid: bool
    revoked: bool = False
    reasons: tuple[str, ...] = field(default_factory=tuple)

    def raise_if_denied(self) -> None:
        if not self.allowed:
            raise VerificationDenied(list(self.reasons))


class ModelGuard:
    """Primary entry point for the ModelGuard Python SDK.

    ``storage_root`` configures the local, file-backed registry,
    provenance store, and audit log used by ``register``, ``resolve``,
    ``revoke``, and the lineage query methods. It is optional because
    Phase 1's inspect/sign/verify workflow needs no persistent state;
    pass it (or call the registry-touching methods without it) and a
    clear error explains what to configure.
    """

    def __init__(self, storage_root: str | Path | None = None) -> None:
        self._storage_root = Path(storage_root) if storage_root else None

    @property
    def registry(self) -> LocalRegistry:
        return LocalRegistry(self._require_storage_root() / "registry")

    @property
    def provenance_store(self) -> LocalProvenanceStore:
        return LocalProvenanceStore(self._require_storage_root() / "provenance" / "events.jsonl")

    def _require_storage_root(self) -> Path:
        if self._storage_root is None:
            raise ModelGuardError(
                "This operation requires local storage. Construct ModelGuard with "
                "a storage_root, e.g. ModelGuard(storage_root='./.modelguard')."
            )
        return self._storage_root

    def inspect(self, artifact_path: str | Path) -> ArtifactDigest:
        """Hash and inspect a local artifact without signing or verifying it."""
        return hash_artifact(Path(artifact_path))

    def build_manifest(
        self, artifact_path: str | Path, metadata: DeclaredMetadata | None = None
    ) -> Manifest:
        return build_manifest(Path(artifact_path), metadata)

    def generate_mbom(
        self, manifest: Manifest, provenance: DeclaredProvenance | None = None
    ) -> MLBOM:
        return generate_mbom(manifest, provenance)

    def sign(self, manifest: Manifest, mbom: MLBOM, keypair: LocalKeyPair) -> SignatureEnvelope:
        return sign_artifact(manifest, mbom, keypair)

    def verify(
        self,
        artifact_path: str | Path,
        mbom_path: str | Path,
        signature_path: str | Path,
    ) -> VerificationResult:
        """Verify a previously signed artifact against its ML-BOM and
        detached signature.

        This never raises for an expected verification failure (invalid
        signature, tampered artifact, mismatched ML-BOM); those become
        ``allowed=False`` with an explanatory reason. It only raises for
        unexpected conditions such as a missing file.
        """
        path = Path(artifact_path)
        mbom = MLBOM.model_validate(json.loads(Path(mbom_path).read_text()))
        envelope = SignatureEnvelope.model_validate(
            json.loads(Path(signature_path).read_text())
        )

        reasons: list[str] = []

        signature_valid = True
        try:
            check_signature_bytes(envelope)
        except ModelGuardError as exc:
            signature_valid = False
            reasons.append(str(exc))

        mbom_valid = check_mbom_digest(mbom, envelope)
        if not mbom_valid:
            reasons.append(
                "The supplied ML-BOM does not match the mbom_digest bound in "
                "the signature."
            )

        try:
            tamper_result = check_artifact_digest(path, envelope)
            digest_matches = tamper_result.matches
            current_digest = tamper_result.current_digest
            if not digest_matches:
                reasons.append(
                    f"Artifact digest mismatch: expected {tamper_result.signed_digest}, "
                    f"got {tamper_result.current_digest}. The artifact may have been "
                    "modified after signing."
                )
        except ModelGuardError as exc:
            digest_matches = False
            current_digest = envelope.payload.artifact_digest
            reasons.append(str(exc))

        allowed = signature_valid and mbom_valid and digest_matches

        # If a local registry is configured and this artifact is
        # registered under a model_id, a revocation of that version
        # must deny verification even though the signature and digest
        # are still cryptographically valid -- revocation is a policy
        # fact layered on top of, not a replacement for, cryptographic
        # integrity.
        revoked = False
        if self._storage_root is not None and envelope.payload.model_id and envelope.payload.version:
            revocation = self.registry.is_revoked(
                envelope.payload.model_id, envelope.payload.version
            )
            if revocation is not None:
                revoked = True
                allowed = False
                reasons.append(
                    f"Model {revocation.model_id}@{revocation.version} was revoked by "
                    f"{revocation.revoked_by}: {revocation.reason}"
                )

        return VerificationResult(
            allowed=allowed,
            artifact_digest=current_digest,
            signature_valid=signature_valid,
            mbom_valid=mbom_valid,
            revoked=revoked,
            reasons=tuple(reasons),
        )

    def load_public_key(self, path: str | Path) -> Ed25519PublicKey:
        return load_public_key(Path(path))

    # -- registry ----------------------------------------------------

    def register(
        self, manifest: Manifest, mbom: MLBOM, actor: str
    ) -> RegistryRecord:
        """Register a manifest + ML-BOM pair under the manifest's
        declared ``model_id``/``version``.

        Raises if ``model_id`` or ``version`` is missing (a registry
        entry without either is not resolvable by name), or if that
        model_id/version pair is already registered.
        """
        if not manifest.model_id or not manifest.version:
            raise ModelGuardError(
                "Registering a model requires both model_id and version to be set "
                "on the manifest."
            )
        record = RegistryRecord(
            model_id=manifest.model_id,
            version=manifest.version,
            artifact_digest=f"{manifest.algorithm}:{manifest.digest}",
            manifest=manifest,
            mbom=mbom,
            registered_by=actor,
        )
        return self.registry.register(record)

    def resolve(self, model_id: str, version: str) -> RegistryRecord | None:
        return self.registry.get(model_id, version)

    def resolve_by_digest(self, artifact_digest: str) -> RegistryRecord | None:
        return self.registry.get_by_digest(artifact_digest)

    def revoke(self, model_id: str, version: str, actor: str, reason: str) -> RevocationRecord:
        record = RevocationRecord(
            model_id=model_id, version=version, revoked_by=actor, reason=reason
        )
        return self.registry.revoke(record)

    def is_revoked(self, model_id: str, version: str) -> RevocationRecord | None:
        return self.registry.is_revoked(model_id, version)

    # -- provenance ----------------------------------------------------

    def record_provenance(
        self,
        subject_id: str,
        relationship: RelationshipType,
        object_id: str,
        actor: str,
        evidence: str = "DECLARED",
    ) -> ProvenanceEvent:
        event = ProvenanceEvent(
            subject_id=subject_id,
            relationship=relationship,
            object_id=object_id,
            actor=actor,
            evidence=evidence,  # type: ignore[arg-type]
        )
        return self.provenance_store.record(event)

    def parents(self, model_id: str) -> list[ProvenanceEvent]:
        return parents(self.provenance_store, model_id)

    def children(self, model_id: str) -> list[ProvenanceEvent]:
        return children(self.provenance_store, model_id)

    def lineage(self, model_id: str) -> list[ProvenanceEvent]:
        return lineage(self.provenance_store, model_id)

    def find_models_derived_from(self, base_model_id: str) -> list[str]:
        return find_models_derived_from(self.provenance_store, base_model_id)

    def find_deployments_using_revoked_model(self) -> list[ProvenanceEvent]:
        """Find DEPLOYED_TO events for any model that is currently
        revoked, or transitively derived from a currently-revoked model.
        """
        revoked_ids: set[str] = set()
        for event in self.provenance_store.all_events():
            for candidate_id in (event.subject_id, event.object_id):
                if self.registry.list_versions(candidate_id):
                    for v in self.registry.list_versions(candidate_id):
                        if self.registry.is_revoked(candidate_id, v):
                            revoked_ids.add(candidate_id)
        return find_deployments_using_revoked_model(self.provenance_store, revoked_ids)
