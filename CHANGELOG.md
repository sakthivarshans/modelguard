# Changelog

All notable changes to this project are documented here. This project
follows semantic versioning once it reaches 1.0; pre-1.0 minor versions
may include breaking changes, which will be called out explicitly.

## [0.5.0] - Phase 5: CI/CD, caching, admission, trust roots

### SECURITY FIX -- read this first

- **`modelguard policy check` / `ModelGuard.check_policy()` returned
  `ALLOW` (exit 0) for a tampered artifact in 0.3.0 and 0.4.0.** The
  policy context received `signature_valid`, which is a check on the
  signature *bytes* and stays `True` when the artifact is modified;
  nothing passed it whether the artifact digest still matched. Only
  `modelguard verify` caught tampering. A Phase 3 test asserted the
  wrong behavior (`ALLOW`) with a comment noting the gap. Fixed:
  a digest mismatch is now an **unconditional DENY** (`artifact_integrity`,
  not a configurable rule, cannot be weakened by any policy). If you
  gated CI or deployments on `policy check` with 0.3.0/0.4.0, treat
  those gates as not having detected post-signing modification.

### Added

- **Trust roots.** `ModelGuard(trusted_key_fingerprints=[...])`,
  `--trusted-fingerprint` (repeatable) on `verify`/`policy check`, new
  `modelguard fingerprint KEYFILE` command (`keygen` also prints the
  fingerprint), and `modelguard.signing.trust`. A fingerprint is the
  SHA-256 of the raw Ed25519 public key. When configured, a valid
  signature from any other key is denied. Empty or malformed
  fingerprints raise `TrustConfigurationError` rather than silently
  never matching.
- New policy rule `require_trusted_signer` (eight rules now). Fails
  closed if no trust roots were configured.
- `VerificationResult` gained `digest_matches`, `signer_trusted`
  (`None` = not checked), `revocation_checked`, `digest_from_cache`.
  Fail-closed defaults.
- **Digest cache** (`modelguard.cache.CachedHasher`, opt-in via
  `ModelGuard(cache_dir=...)` / `--cache-dir`). Caches only the digest
  computation, keyed on file metadata (size, mtime, ctime, inode,
  device) with git-style racy-timestamp handling. Signature, ML-BOM,
  trust, revocation, and policy are always recomputed, so a warm cache
  cannot override a new revocation. See `docs/limitations.md` for the
  trust assumptions.
- **Admission hook** `modelguard.admission.admit()` -> `AdmissionDecision`
  (+ `AdmissionDenied`). Fails closed on missing trust roots, any
  exception, or an audit-write failure; independently requires an
  untampered artifact and trusted signer regardless of policy. Optional
  hash-chained audit record (`deployment.admission` event).
- `ModelGuard.check_policy_detailed()` returning `PolicyCheck`
  (decision + verification + scan report).
- `hashing.artifact_digest_from_files()`: the single home of the
  artifact-digest rules (`hash_directory` now uses it).
- Examples: `examples/ci/github-actions-verify-model.yml`,
  `examples/docker/{Dockerfile,entrypoint.sh}`,
  `examples/admission/deploy_gate.py`. `examples/policies/production.yaml`
  now enables `require_trusted_signer`.

### Changed

- **Breaking (pre-1.0):** `policy.build_context()` now requires the
  keyword `artifact_digest_matches`.
- `check_policy()` no longer hashes the artifact twice (`run_scanners`
  accepts an `artifact_digest` computed by the caller in the same
  operation). Roughly halves uncached `check_policy` time on large
  models.
- `verify` text output now says `Signer : NOT CHECKED` and
  `Revocation : NOT CHECKED` instead of implying those checks passed.

### Deliberately not done

- No `org.modelguard.verification.status` image label (the product
  document lists one): an image label is an unauthenticated claim, so a
  build-time "verified" label would be exactly the fake assurance the
  project rules forbid. The Docker example uses the id/digest labels
  (informational) and a startup verification (the control).
- Scan results are not cached: they depend on the ML-BOM and scanner
  set, and the measured cost was the redundant hash, now removed.
- No Kubernetes admission webhook; `admit()` is the building block.

## [0.4.0] - Phase 4: Scanning

### Added

- `modelguard.scanning.models`: `Severity` (INFO/LOW/MEDIUM/HIGH/CRITICAL,
  ordered, `.rank`), `Confidence` (LOW/MEDIUM/HIGH), `Finding`,
  `ScanReport` (`.clean`, `.all_scanners_ok`, `.count(severity)`).
- `modelguard.scanning.protocol.Scanner`: the plugin interface every
  scanner implements. Explicitly forbids executing, importing, or
  deserializing artifact content.
- `modelguard.scanning._walk.iter_scannable_files`: a shared,
  symlink-safe file walker. Unlike `modelguard.hashing.digest`, which
  fails closed and raises on any symlink, scanning skips a symlink and
  reports a LOW-severity `scan_skipped` finding instead, so one unsafe
  entry does not abort the rest of the scan.
- Three built-in scanners: `UnsafeSerializationScanner` (pickle
  extension + pickle-protocol-header sniffing; never unpickles),
  `SecretScanner` (a narrow, high-confidence pattern set -- AWS access
  key IDs, PEM private key headers, GitHub PATs, Slack tokens; skips
  oversized/binary files; never echoes matched secret text into a
  finding), `MetadataCompletenessScanner` (informational-only: missing
  license, lineage, or model identity).
- `modelguard.scanning.run_scanners`: orchestrates `DEFAULT_SCANNERS`
  (all three above) against an artifact, isolating each scanner in its
  own try/except so a raising scanner is recorded as `"error"` rather
  than crashing the run or being silently treated as "found nothing".
- Two new policy rules: `max_critical_findings`, `max_high_findings`.
  `RuleConfig` gained a `max_count` field for them. Both **fail
  closed**: enabling either rule without a scan having run denies
  rather than treating "no scan" as "zero findings" -- see
  `PolicyEvaluationContext.scan_performed`.
- SDK: `ModelGuard.scan(artifact, manifest=None, mbom=None)`.
  `ModelGuard.check_policy(...)` now always runs a scan as part of
  every policy check and feeds CRITICAL/HIGH finding counts into
  `build_context()`.
- CLI: `modelguard scan PATH [--manifest ...] [--mbom ...]
  [--fail-on info|low|medium|high|critical] [--format json]`, with
  text and JSON output and exit codes matching the existing
  `verify`/`policy check` conventions (0 clean, 2 a blocking finding or
  scanner error, 1 unexpected error).
- `examples/policies/production.yaml` now enables `max_critical_findings`
  (deny) and `max_high_findings` (review) at `max_count: 0`.
- 49 new tests (unit + security), bringing the suite to 162 tests.
  `ruff check` and `mypy --strict` both remain clean.

### Design decisions

- Scanners are format/pattern-level only, never behavioral: detecting
  "this pickle's opcodes construct a dangerous object" would require
  parsing (and is not far from executing) the pickle stream, which is
  explicitly out of scope. The unsafe-serialization scanner reads at
  most 8 bytes per file for its header sniff and never calls
  `pickle.load` or any other deserializer.
- The secret scanner is deliberately narrow (four pattern families)
  rather than a general-purpose secret scanner with entropy analysis --
  precision over recall, to keep the false-positive rate low enough
  that a `max_critical_findings: 0` policy is usable in practice.
- `iter_scannable_files` skips-and-reports a symlink rather than
  failing closed the way `modelguard.hashing.digest` does. Hashing is
  the security-critical identity computation and must never silently
  proceed past unsafe input; scanning is best-effort defense-in-depth,
  so aborting an entire scan over one symlink would throw away
  legitimate findings elsewhere in the artifact for no security
  benefit -- the symlink is still never followed either way.
- `max_critical_findings`/`max_high_findings` fail closed on
  `scan_performed=False` rather than defaulting to "0 findings, so
  pass". A policy author who enables either rule is asking for
  scan-backed evidence; silently treating "no scan happened" as "the
  scan found nothing" would be exactly the kind of fake completeness
  the project's engineering rules forbid.

### Known limitations

See `docs/limitations.md` and the Phase 4 addendum in
`docs/security/threat-model.md`. In particular: no dependency
scanning, no container scanning, no license-allowlist scanning, no
opcode-level pickle analysis, no recursive archive inspection, and no
suppression/status workflow for findings beyond a fixed `status="open"`
field. Scan reports are not signed or otherwise cryptographically
bound into the manifest/ML-BOM/signature chain -- they are local,
unsigned observations.

## [0.3.0] - Phase 3: Policy Engine

### Added

- `modelguard.policy.models`: `Decision` enum (ALLOW, ALLOW_WITH_WARNINGS,
  REVIEW_REQUIRED, QUARANTINE, DENY, REVOKED) ordered by severity,
  `RuleConfig`, `PolicyDocument`, `RuleResult`, explainable
  `PolicyDecisionResult` (`.explain()`).
- `modelguard.policy.loader`: safe (`yaml.safe_load`-only) policy
  loading with strict schema validation -- unknown top-level fields,
  unknown `policy:` fields, and unknown rule names are all rejected
  rather than silently ignored (`UnknownRuleError`,
  `PolicyValidationError`).
- `modelguard.policy.engine`: deterministic, pure-function evaluation
  of five rules -- `require_valid_signature`, `require_ml_bom`,
  `require_known_lineage`, `require_license`, `reject_revoked_models`
  -- each with a configurable `on_fail` action
  (`warn`/`review`/`quarantine`/`deny`). The overall decision is the
  most severe triggered outcome. `reject_revoked_models` always
  escalates to `REVOKED` regardless of its configured `on_fail`.
- SDK: `ModelGuard.check_policy(artifact, mbom, signature, policy)`,
  combining `verify()` with policy evaluation in one call.
- CLI: `modelguard policy validate|check`, with per-decision exit
  codes (0 allowed, 2 deny, 3 review required, 4 quarantine, 5
  revoked, 1 error).
- Example policies: `examples/policies/production.yaml`,
  `examples/policies/development.yaml`.
- 33 new tests (unit + security), bringing the suite to 113 tests.
  `ruff check` and `mypy --strict` both remain clean.
- New core dependency: PyYAML (policy files are YAML by design, per
  the product document; `yaml.safe_load` is used exclusively).

### Design decisions

- Only five rules are implemented -- exactly the ones ModelGuard can
  honestly evaluate today. Rules described in the product document
  that depend on data ModelGuard does not yet produce (vulnerability
  counts, risk classification, trusted-publisher lists) are not
  accepted by the schema at all, rather than accepted and silently
  treated as always-passing.
- `reject_revoked_models` hardcodes its escalation to `REVOKED` in
  engine code rather than trusting the policy author's `on_fail`
  configuration for that one rule, since a misconfigured or malicious
  policy setting it to `warn` would otherwise let a revoked model
  through -- defeating the purpose of revocation.

### Known limitations

See `docs/limitations.md` and the Phase 3 addendum in
`docs/security/threat-model.md`. In particular: no policy simulation/
dry-run mode, and `ModelGuard.check_policy()` only considers
license/lineage data from the ML-BOM (not the original manifest file),
since it reconstructs a minimal manifest from the signature payload.

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
