# Changelog

All notable changes to this project are documented here. This project
follows semantic versioning once it reaches 1.0; pre-1.0 minor versions
may include breaking changes, which will be called out explicitly.

## [0.2.0] - Phase 2: Local Registry and Provenance

### Added

- `modelguard.audit.chain`: a generic hash-chained, tamper-evident
  append-only log primitive, shared by the audit log, the registry's
  revocation history, and the provenance store.
- `modelguard.audit.log.LocalAuditLog` and `AuditEvent`.
- `modelguard.registry`: `Registry` protocol, `LocalRegistry`
  (register/resolve by name or digest/list versions/revoke/unrevoke),
  `RegistryRecord`, `RevocationRecord`. Duplicate registration of an
  existing `model_id`/`version` is rejected; registry identifiers are
  validated against path traversal.
- `modelguard.provenance`: `ProvenanceEvent`, `RelationshipType`,
  `LocalProvenanceStore`, and graph queries `parents`, `children`,
  `lineage`, `find_models_derived_from`,
  `find_deployments_using_revoked_model` (cycle-safe).
- SDK: `ModelGuard(storage_root=...)`, `register`, `resolve`,
  `resolve_by_digest`, `revoke`, `is_revoked`, `record_provenance`,
  `parents`, `children`, `lineage`, `find_models_derived_from`,
  `find_deployments_using_revoked_model`.
- `ModelGuard.verify()` is now revocation-aware: denies a revoked
  model even when its signature and digest are still valid. Adds a
  `revoked` field to `VerificationResult`.
- CLI: `modelguard register|resolve|revoke|lineage|provenance record`,
  and `modelguard verify --storage-root` for revocation-aware
  verification.
- 37 new tests (unit + security), bringing the suite to 80 tests.
  `ruff check` and `mypy --strict` both remain clean.

### Design decisions

- Phase 2 is implemented as a **local, file-backed** registry and
  provenance store behind `Protocol` interfaces, rather than the
  FastAPI + PostgreSQL service described in the architecture document.
  This follows the project's own MVP rule ("the first implementation
  must work without external services") and keeps this phase testable
  without a database. A PostgreSQL-backed `Registry` implementation is
  future work and should be a drop-in adapter behind the same protocol.

### Known limitations

See `docs/limitations.md` and the Phase 2 addendum in
`docs/security/threat-model.md`. In particular: hash-chain integrity
is not verified automatically on every read (must call `.verify()`
explicitly), tail-truncation of a hash-chained log is undetectable,
and the local registry/provenance/audit files assume a single writer.

## [0.1.0] - Phase 1: Local Core

### Added

- Deterministic SHA-256 hashing for files and directories
  (`modelguard.hashing`), with documented path-normalization,
  symlink-rejection, and timestamp-exclusion rules.
- Canonical, schema-versioned `Manifest` model (`modelguard.manifest`).
- Minimal CycloneDX-envelope-shaped ML-BOM generator with per-field
  evidence levels (`modelguard.mbom`).
- Local Ed25519 keypair generation, signing, and verification
  (`modelguard.signing`), with a signature payload binding artifact
  digest, ML-BOM digest, model identity, signer identity, and time.
- High-level `ModelGuard` SDK facade (`modelguard.ModelGuard`) and
  `VerificationResult`.
- CLI: `modelguard inspect|digest|manifest|mbom generate|keygen|sign|verify`,
  with `--format json` and CI-friendly exit codes (0 allowed, 2 denied,
  1 error).
- Unit, security, and CLI integration tests (43 tests). `ruff check`
  and `mypy --strict` both pass with zero issues.
- Documentation: `docs/limitations.md`, `docs/security/threat-model.md`,
  a runnable example under `examples/basic_verification/`.

### Known limitations

See `docs/limitations.md`. In particular: no policy engine, no
registry, no scanners, no revocation, and no trust-root check on the
signer's public key yet -- `verify()` currently accepts any valid
signature regardless of which key produced it.
