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
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from modelguard.cache import CachedHasher
from modelguard.exceptions import ModelGuardError, VerificationDenied
from modelguard.hashing.digest import ArtifactDigest, hash_artifact
from modelguard.manifest.builder import DeclaredMetadata, build_manifest
from modelguard.manifest.models import Manifest
from modelguard.mbom.generator import DeclaredProvenance, generate_mbom
from modelguard.mbom.models import MLBOM
from modelguard.policy.engine import build_context, evaluate
from modelguard.policy.loader import load_policy_file
from modelguard.policy.models import PolicyDecisionResult
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
from modelguard.registry.protocol import Registry
from modelguard.scanning import ScanReport, Severity, run_scanners
from modelguard.signing.envelope import SignatureEnvelope, load_envelope
from modelguard.signing.keys import LocalKeyPair, load_public_key
from modelguard.signing.providers import SignerProvider
from modelguard.signing.signer import sign_artifact, sign_with_provider
from modelguard.signing.trust import normalize_fingerprints
from modelguard.signing.verifier import (
    SignatureCheck,
    check_artifact_digest,
    check_mbom_digest,
    verify_envelope_signature,
)


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """Structured outcome of ``ModelGuard.verify()``.

    ``allowed`` means: the signature is cryptographically valid, the
    artifact on disk matches the signed digest, the ML-BOM matches, the
    model is not revoked (when a registry is configured), and -- when
    trusted key fingerprints are configured -- the signing key is one
    of them. It does not reflect policy evaluation or scanning.

    Read ``signer_trusted`` alongside ``allowed``: when it is ``None``
    no trust roots were configured, so ``allowed`` says nothing about
    *who* signed (anyone can sign with a freshly generated key).
    Likewise ``revocation_checked`` is ``False`` when no registry was
    consulted, in which case ``revoked=False`` means "not checked",
    not "checked and clear".
    """

    allowed: bool
    artifact_digest: str
    signature_valid: bool
    mbom_valid: bool
    revoked: bool = False
    reasons: tuple[str, ...] = field(default_factory=tuple)
    # Fail-closed defaults: a result constructed without these facts
    # never claims integrity or trust.
    digest_matches: bool = False
    signer_trusted: bool | None = None
    revocation_checked: bool = False
    digest_from_cache: bool = False
    # What actually verified the signature (None when it did not verify).
    signature_algorithm: str | None = None
    signer_key_fingerprint: str | None = None

    def raise_if_denied(self) -> None:
        if not self.allowed:
            raise VerificationDenied(list(self.reasons))


@dataclass(frozen=True, slots=True)
class PolicyCheck:
    """A policy decision together with the evidence it was based on.

    Returned by ``ModelGuard.check_policy_detailed()``. Deployment
    admission needs the verification facts (digest, trust, revocation
    coverage, cache use) alongside the decision, and a bare
    ``PolicyDecisionResult`` does not carry them.
    """

    decision: PolicyDecisionResult
    verification: VerificationResult
    scan_report: ScanReport


class ModelGuard:
    """Primary entry point for the ModelGuard Python SDK.

    ``storage_root`` configures the local, file-backed registry,
    provenance store, and audit log used by ``register``, ``resolve``,
    ``revoke``, and the lineage query methods. It is optional because
    Phase 1's inspect/sign/verify workflow needs no persistent state;
    pass it (or call the registry-touching methods without it) and a
    clear error explains what to configure.

    ``trusted_key_fingerprints`` are the SHA-256 fingerprints of the
    public keys whose signatures the caller accepts (see
    ``modelguard.signing.trust``). Leave it ``None`` and no signer is
    considered trusted; ``verify()`` still works but reports
    ``signer_trusted=None``. An empty collection raises
    ``TrustConfigurationError``.

    ``registry`` injects any object implementing the ``Registry``
    protocol (e.g. ``modelguard.registry.postgres.PostgresRegistry``).
    When given, it is used for registration, resolution, and the
    revocation check in ``verify()`` instead of the local file registry.
    Provenance and audit remain local (``storage_root``).

    ``allow_legacy_signatures=False`` refuses format-version-1 signatures
    (written by ModelGuard <= 0.6.0), which do not commit to the signing
    key. Leave it ``True`` only while old signatures still need to verify.

    ``cache_dir`` opts in to the local digest cache
    (``modelguard.cache``); nothing is written to disk for caching
    unless it is set.
    """

    def __init__(
        self,
        storage_root: str | Path | None = None,
        *,
        cache_dir: str | Path | None = None,
        trusted_key_fingerprints: Iterable[str] | None = None,
        registry: Registry | None = None,
        allow_legacy_signatures: bool = True,
    ) -> None:
        self._allow_legacy_signatures = allow_legacy_signatures
        self._storage_root = Path(storage_root) if storage_root else None
        self._injected_registry = registry
        self._hasher: CachedHasher | None = CachedHasher(Path(cache_dir)) if cache_dir else None
        self._trusted: frozenset[str] | None = (
            normalize_fingerprints(trusted_key_fingerprints)
            if trusted_key_fingerprints is not None
            else None
        )

    @property
    def trusted_key_fingerprints(self) -> frozenset[str] | None:
        return self._trusted

    @property
    def registry(self) -> Registry:
        if self._injected_registry is not None:
            return self._injected_registry
        return LocalRegistry(self._require_storage_root() / "registry")

    @property
    def _has_registry(self) -> bool:
        return self._injected_registry is not None or self._storage_root is not None

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

    def sign_with_provider(
        self, manifest: Manifest, mbom: MLBOM, provider: SignerProvider
    ) -> SignatureEnvelope:
        """Sign with any ``SignerProvider`` (local key, KMS, HSM, ...)."""
        return sign_with_provider(manifest, mbom, provider)

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
        envelope = load_envelope(Path(signature_path))

        reasons: list[str] = []

        signature_valid = True
        signature_check: SignatureCheck | None = None
        try:
            signature_check = verify_envelope_signature(
                envelope, allow_legacy_v1=self._allow_legacy_signatures
            )
        except ModelGuardError as exc:
            signature_valid = False
            reasons.append(str(exc))

        mbom_valid = check_mbom_digest(mbom, envelope)
        if not mbom_valid:
            reasons.append(
                "The supplied ML-BOM does not match the mbom_digest bound in "
                "the signature."
            )

        digest_from_cache = False

        def _hash(target: Path) -> ArtifactDigest:
            nonlocal digest_from_cache
            if self._hasher is None:
                return hash_artifact(target)
            outcome = self._hasher.hash(target)
            digest_from_cache = outcome.from_cache
            return outcome.digest

        try:
            tamper_result = check_artifact_digest(path, envelope, _hash)
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

        # Trust roots are checked against the fingerprint of the key that
        # actually verified the signature (computed by the verifier from
        # the key bytes, never read from a claimed field), and only when
        # configured. ``None`` (not configured) is reported as such,
        # never as trusted.
        signer_trusted: bool | None = None
        if self._trusted is not None:
            verified_fingerprint = signature_check.key_fingerprint if signature_check else None
            signer_trusted = verified_fingerprint is not None and verified_fingerprint in self._trusted
            if not signer_trusted and verified_fingerprint is not None:
                reasons.append(
                    f"The signing key (fingerprint {verified_fingerprint}) is not in "
                    "the configured set of trusted key fingerprints."
                )

        allowed = signature_valid and mbom_valid and digest_matches and signer_trusted is not False

        # If a local registry is configured and this artifact is
        # registered under a model_id, a revocation of that version
        # must deny verification even though the signature and digest
        # are still cryptographically valid -- revocation is a policy
        # fact layered on top of, not a replacement for, cryptographic
        # integrity.
        revoked = False
        revocation_checked = False
        if self._has_registry and envelope.payload.model_id and envelope.payload.version:
            revocation_checked = True
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
            digest_matches=digest_matches,
            signer_trusted=signer_trusted,
            revocation_checked=revocation_checked,
            digest_from_cache=digest_from_cache,
            signature_algorithm=signature_check.algorithm if signature_check else None,
            signer_key_fingerprint=signature_check.key_fingerprint if signature_check else None,
        )

    def load_public_key(self, path: str | Path) -> Ed25519PublicKey:
        return load_public_key(Path(path))

    # -- scanning ----------------------------------------------------

    def scan(
        self,
        artifact_path: str | Path,
        manifest: Manifest | None = None,
        mbom: MLBOM | None = None,
    ) -> ScanReport:
        """Run the default scanner set against a local artifact.

        Passing ``manifest``/``mbom`` when available lets the metadata-
        completeness scanner check declared fields; omit them to scan
        artifact bytes only (unsafe-serialization and secret findings
        are unaffected either way).
        """
        return run_scanners(Path(artifact_path), manifest, mbom)

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

    # -- policy ----------------------------------------------------

    def check_policy(
        self,
        artifact_path: str | Path,
        mbom_path: str | Path,
        signature_path: str | Path,
        policy_path: str | Path,
    ) -> PolicyDecisionResult:
        """Run verification and a scan, then evaluate a policy against
        the combined result.

        This is the single call CI/CD should use: it combines
        ``verify()`` (signature, digest, ML-BOM, trust, revocation) with
        a scan (so ``max_critical_findings``/``max_high_findings`` rules
        have real finding counts to evaluate) and policy-as-code
        evaluation, returning one explainable decision. A digest
        mismatch always yields DENY regardless of the policy -- see
        ``modelguard.policy.engine.evaluate``.

        Use ``check_policy_detailed()`` if you also need the
        verification facts behind the decision.
        """
        return self.check_policy_detailed(
            artifact_path, mbom_path, signature_path, policy_path
        ).decision

    def check_policy_detailed(
        self,
        artifact_path: str | Path,
        mbom_path: str | Path,
        signature_path: str | Path,
        policy_path: str | Path,
    ) -> PolicyCheck:
        """Like ``check_policy`` but also returns the ``VerificationResult``
        and ``ScanReport`` the decision was based on.
        """
        path = Path(artifact_path)
        mbom = MLBOM.model_validate(json.loads(Path(mbom_path).read_text()))

        verification = self.verify(path, mbom_path, signature_path)

        # Reconstruct a Manifest good enough for policy rules (license,
        # model_id, version) from the signature payload and mbom, since
        # verify() only returns booleans, not the manifest itself.
        envelope = SignatureEnvelope.model_validate(json.loads(Path(signature_path).read_text()))
        manifest = Manifest(
            artifact_type="file" if path.is_file() else "directory",
            digest=verification.artifact_digest.split(":", 1)[-1],
            model_id=envelope.payload.model_id,
            version=envelope.payload.version,
        )

        # Reuse the digest verify() just computed instead of hashing the
        # artifact a second time -- but only when it really is the
        # digest of what is on disk. If hashing failed or mismatched,
        # ``artifact_digest`` may be the *claimed* digest from the
        # signature, which must never label a scan report.
        scan_report = run_scanners(
            path,
            manifest,
            mbom,
            artifact_digest=verification.artifact_digest if verification.digest_matches else None,
        )

        policy = load_policy_file(Path(policy_path))
        context = build_context(
            manifest,
            mbom,
            signature_valid=verification.signature_valid,
            mbom_valid=verification.mbom_valid,
            revoked=verification.revoked,
            artifact_digest_matches=verification.digest_matches,
            signer_trusted=verification.signer_trusted,
            scan_performed=True,
            critical_finding_count=scan_report.count(Severity.CRITICAL),
            high_finding_count=scan_report.count(Severity.HIGH),
        )
        return PolicyCheck(
            decision=evaluate(context, policy),
            verification=verification,
            scan_report=scan_report,
        )
