# Changelog

All notable changes to this project are documented here. This project
follows semantic versioning once it reaches 1.0; pre-1.0 minor versions
may include breaking changes, which will be called out explicitly.

## [0.9.0] - Phase 7 slice 7c: key management (KMS, HSM, rotation CLI)

### Added

- **`modelguard.signing.kms.KmsSignerProvider`**: `SignerProvider`
  backed by AWS KMS (`ECC_NIST_P256`, `ecdsa-p256-sha256`). Uses
  `MessageType="RAW"` exclusively, after empirically confirming
  `"DIGEST"` mode produces signatures that don't verify against
  `cryptography` even when moto's own `Verify` reports them valid.
  Requires the new `kms` extra.
- **`modelguard.signing.hsm.Pkcs11SignerProvider`**: `SignerProvider`
  backed by any PKCS#11 token (EC P-256). Hashes on the host before
  calling the token's raw `ECDSA` mechanism (the only one most tokens,
  SoftHSM2 included, actually expose) and converts between PKCS#11's
  raw `r || s` signature / `CKA_EC_POINT` public key and the DER /
  uncompressed-point wire format the `ecdsa-p256-sha256` scheme
  expects. Requires the new `hsm` extra. Includes
  `generate_ec_keypair()`, a provisioning helper for bootstrapping a
  token (used by this project's own tests against a real SoftHSM2
  token).
- Trust configuration rotation CLI: `modelguard trust add-key`,
  `retire-key`, `revoke-key`, `remove-key` -- mutate a trust config
  file in place, atomically, with the same schema validation as
  loading one.

### Security

- Both new providers fail closed on every failure mode (wrong key
  type, missing key, wrong PIN/credentials, oversized message, network
  error), converting to `SigningProviderError` with only the exception
  type name -- whether called directly or through
  `sign_with_provider`, which already re-verifies every signature
  against the provider's own reported public key before returning an
  envelope (unchanged from 7a, and still the backstop against a
  provider whose `sign()` and `public_key()` disagree).
- Two bugs found and fixed during manual end-to-end testing of the
  rotation CLI, before any test was written for them (both now have
  regression tests): `retire-key`/`revoke-key` used
  `model_copy(update=...)`, which assigns directly into `__dict__` and
  skips validation entirely, so a `--not-after` string was stored
  un-parsed instead of becoming a real, checked `datetime` -- silently
  defeating the naive-timestamp rejection; and every rotation command
  let a raw `pydantic.ValidationError` escape as an unhandled
  traceback instead of the same clean `Error: ...` message every other
  malformed-input path in this project produces.

### Testing

- 43 new tests: 9 for the KMS provider against a real moto KMS
  emulator (end-to-end sign+verify, key-spec rejection, wrong-usage-key
  failure, nonexistent key, oversized-message pre-check, exception-text
  leakage, public-key caching, missing-extra error), 11 for the HSM
  provider against a real, freshly-provisioned SoftHSM2 token
  (end-to-end sign+verify, point/signature shape checks, wrong PIN,
  missing key/token, a synthetic wrong-length-signature test since
  SoftHSM2 never produces one naturally, idempotent close, missing-extra
  error), 14 for the trust rotation CLI (including the two regression
  tests above and a full add/retire/remove rotation workflow), and 9
  new mutation-checks across the KMS key-spec check, the HSM
  signature-length check, and the CLI's not-found detection -- one of
  which (the HSM length check) was initially **not** caught because no
  existing test exercised that path; a targeted test was added and the
  mutation re-run to confirm it now is, per the project's test-honesty
  requirement to report and fix gaps rather than quietly move on.
- Verified empirically, with no optional dependencies installed at
  all (a bare venv, no boto3/psycopg/pkcs11/asn1crypto), that
  `import modelguard` and `from modelguard.cli.main import cli` both
  still succeed -- `kms.py` and `hsm.py` are excluded from
  `modelguard.signing`'s package-level exports, imported only where
  actually used, matching the existing `storage/s3.py` precedent.

## [0.8.0] - Phase 7 slice 7b: trust configuration

### Added

- **`modelguard.signing.trust_config.TrustConfig`**: a strict-schema,
  safe-YAML-loaded set of trusted keys, replacing the flat fingerprint
  set with per-key `status` (active/retired/revoked), `not_before`/
  `not_after` (timezone-required), optional `algorithm` pinning,
  optional `signer_identity` binding, and optional
  `scope_model_id_patterns`. A fingerprint may appear at most once.
- **`evaluate_trust()`**: decides trust from what actually verified a
  signature (fingerprint and algorithm from `SignatureCheck`) against
  the trust configuration and the **verifier's own clock**. Deliberately
  takes no signature-timestamp parameter, so expiry and revocation
  cannot be influenced by a signature's claimed (attacker-controlled)
  `signed_at`.
- **`load_trust_config_file()`**: size-capped, `yaml.safe_load`-only
  loader with the same "malformed input fails as one exception type"
  discipline as the policy and envelope loaders.
- **`build_minimal_trust_config()`** / **`merge_trust_configs()`**: turn
  a flat fingerprint list into an unconstrained `TrustConfig`
  (backward-compatible with `--trusted-fingerprint`), and combine
  multiple sources, rejecting genuinely conflicting duplicate entries
  rather than silently picking one.
- SDK: `ModelGuard(trust_config=...)`, combinable with
  `trusted_key_fingerprints`; new `ModelGuard.trust_config` property.
- CLI: `--trust-config PATH` on `verify` and `policy check`;
  `modelguard trust validate PATH` (with `--format json`).

### Backward compatibility

- `--trusted-fingerprint` / `trusted_key_fingerprints=` are unchanged
  and now implemented as an unconstrained `TrustConfig` under the hood.
  `ModelGuard.trusted_key_fingerprints` keeps returning a
  `frozenset[str] | None` as before.
- `admission.admit()`'s trust-root gate (`guard.trusted_key_fingerprints
  is None`) is unaffected: it is populated whether trust came from
  `trusted_key_fingerprints`, `trust_config`, or both.

### Security

- Closes the gap where trust was all-or-nothing per key forever: a key
  can now be time-bounded, retired, or revoked, and revocation is
  effective for every verification from that moment on regardless of
  what signing time any signature -- forged or genuine -- claims (see
  the addendum in `docs/security/threat-model.md` for the specific
  backdating threat this defends against and what it still cannot
  prove without a trusted timestamp or transparency log).
- The trust configuration file joins policy files as an asset in the
  threat model's "Policy Bypass" category: this release makes the
  file's *parsing and evaluation* safe, not its *access control* --
  who can write the path passed to `--trust-config` remains a
  deployment concern, unchanged from how policy files are already
  treated.

### Testing

- 79 new tests (unit + security): schema validation for every field
  (fingerprint format, algorithm identifier format, timezone-required
  timestamps, bounded/control-character-free strings, duplicate
  rejection), `evaluate_trust()` for every condition alone and in
  combination, hostile-file tests (unsafe YAML tags, oversized file,
  non-UTF-8, YAML anchor expansion, partial-validity file rejection),
  SDK integration (`ModelGuard.verify()` for trust/expiry/revocation/
  scope/identity-binding, combined fingerprint+config sources,
  conflict detection), CLI (`trust validate`, `--trust-config` on
  `verify`/`policy check`), and `admission.admit()` with a
  `trust_config`-only guard.
- Eight of the riskiest checks (status-active gate, algorithm pin,
  duplicate-key rejection, merge-conflict detection, `not_before`/
  `not_after` gates, signer-identity binding, scope matching) were
  mutation-checked: each was deliberately removed, confirmed to make
  its guarding test fail, then restored. All eight caught. (One earlier
  mutation run produced a false "not caught" result due to a stale
  compiled-bytecode artifact from rapid sequential edits within the
  same filesystem timestamp granularity; re-run with bytecode caching
  disabled and a fresh interpreter per check, all eight were correctly
  caught. Noted here per the project's test-honesty requirement to
  report anomalies rather than quietly rerun until green.)

## [0.7.0] - Phase 7 slice 7a: signature-scheme plumbing

### Added

- **`modelguard.signing.schemes`**: a pluggable signature-scheme
  registry, decoupled from key custody. Ships `ed25519` (unchanged
  behavior) and a new `ecdsa-p256-sha256` (uncompressed SEC1 public
  key; DER `ECDSA-Sig-Value` signature; SHA-256). `verifier_registry()`
  builds an extended, still-immutable registry; it refuses to let a
  caller replace a built-in scheme.
- **`modelguard.signing.providers.SignerProvider`**: a small protocol
  (`algorithm`, `identity`, `public_key()`, `sign(message)`) so a
  signature can be produced by something other than a local private key
  file. `LocalEd25519Signer` adapts the existing local-key path onto it.
  `ModelGuard.sign_with_provider()` and
  `modelguard.signing.sign_with_provider()` are new entry points;
  `ModelGuard.sign()` / `sign_artifact()` are unchanged wrappers around
  it and still produce Ed25519 signatures by default.
- **Signature format version 2**: the signed payload now additionally
  covers `signature_algorithm` and `key_id` (SHA-256 fingerprint of the
  signing public key), so neither can be swapped post-signing without
  invalidating the signature. `sign_with_provider()` always produces
  version 2. `verify_envelope_signature()` returns a `SignatureCheck`
  (algorithm, key fingerprint, format version, whether the key was
  signature-bound) computed from what actually verified, not from
  unverified claims.
- **`load_envelope()`**: a single, bounded signature-file loader (size
  cap before parsing, strict UTF-8, unknown fields rejected) used by
  the SDK and CLI, replacing ad hoc `json.loads` + `model_validate`
  call sites. Malformed files now raise the new
  `MalformedSignatureError` instead of a raw `json`/pydantic exception.
- **New exceptions**: `UnsupportedSignatureSchemeError` (subclass of
  `SignatureInvalidError` -- an unknown scheme denies exactly like an
  invalid signature), `MalformedSignatureError`, `SigningProviderError`.
- CLI: `--reject-legacy-signatures` on `verify` and `policy check`
  (refuses format-version-1 signatures); `verify` now prints/returns
  the verifying `signature_algorithm` and `signer_key_fingerprint`.
- SDK: `ModelGuard(allow_legacy_signatures=False)`;
  `VerificationResult.signature_algorithm` /
  `.signer_key_fingerprint`.
- `tests/fixtures/legacy_signature_0_6_0/`: a signature produced by the
  unmodified 0.6.0 signer, checked in as a permanent backward-
  compatibility regression fixture. Never regenerate it with current
  code.

### Backward compatibility

- Format-version-1 (pre-0.7.0) signatures are unaffected: the new
  payload fields are omitted (not null) when unset, so the canonical
  JSON that was actually signed is byte-for-byte identical to before,
  and old signatures verify unchanged. They can be explicitly refused
  with `--reject-legacy-signatures` / `allow_legacy_signatures=False`.
- `check_signature_bytes()` keeps its old signature and behavior; it
  now delegates to `verify_envelope_signature()` internally.
- Ed25519 key fingerprints are computed the same way (SHA-256 of the
  raw 32-byte public key); existing `--trusted-fingerprint` values and
  trust configuration keep working unchanged.

### Security

- Closes an algorithm-confusion gap: previously the unsigned
  `signature_type` field was the only indication of which scheme
  verified a signature. A version-2 payload now signs the algorithm
  itself, and the unsigned label is checked for agreement, not trusted.
- Closes a key-substitution gap: a version-2 payload signs the
  fingerprint of the intended signing key (`key_id`); the verifier
  recomputes the fingerprint from the actual key bytes used and
  compares, rather than trusting whatever key accompanies the
  signature.
- `sign_with_provider()` re-verifies the envelope it produces against
  the provider's own reported public key before returning it, so a
  provider that signs with a different key than it reports (e.g. a
  repointed KMS alias) fails at signing time, not silently.
- Provider exceptions are normalized to `SigningProviderError` carrying
  only the exception type name, with the original cause suppressed, so
  KMS/HSM error text (which can carry ARNs, key IDs, or tokens) never
  reaches logs or CLI output through this path.
- See `docs/security/threat-model.md` (Phase 7 slice 7a addendum) for
  the specific threats, mitigations, and residual risks, and
  `docs/limitations.md` for what this slice explicitly does not cover
  (trust configuration, key rotation, KMS, HSM, Sigstore -- later
  slices).

### Testing

- 75 new tests (unit + security): scheme verifiers (round trips, wrong
  lengths, wrong keys, malformed DER, compressed/off-curve points),
  provider contract and fail-closed paths (leaking exception text,
  mismatched key/signature, unusable return values), envelope-parsing
  attacks (oversized files, deep nesting, non-UTF-8, unknown fields),
  algorithm-confusion and downgrade attempts in both directions,
  key-substitution, and full backward-compatibility checks against the
  checked-in 0.6.0 fixture.
- The riskiest checks (key-substitution binding, algorithm-label
  binding, legacy-scheme fixing) were mutation-checked: each check was
  deliberately removed, confirmed to make its guarding test fail, then
  restored. All three mutants were caught.

## [0.6.0] - Phase 6: PostgreSQL registry and object storage

### Added

- **`PostgresRegistry`** (`modelguard.registry.postgres`, extra
  `postgres`): registry backend on PostgreSQL with checksummed
  migrations, append-only history enforced by database triggers,
  hash-chained revocation events (advisory-lock serialized), verifying
  TLS required for remote hosts, secret-free errors, and fail-closed
  `RegistryBackendError`. Setup guide: `docs/deployment/postgres.md`.
- **`modelguard.storage`**: `BlobStore` protocol, `LocalBlobStore`,
  `S3BlobStore` (extra `s3`; AWS S3 / MinIO-style endpoints), and
  `upload_artifact` / `download_artifact`. Content-addressed; every
  read is hash-verified; hostile manifests are validated after their
  hash matches; downloads are staged and renamed atomically.
- `ModelGuard(registry=...)` accepts any `Registry` implementation;
  `verify()` uses it for the revocation check.
- CLI: `--registry-dsn-env` (verify, policy check, register, resolve,
  revoke); `registry migrate`, `registry verify-chain`; `artifact push`,
  `artifact pull`.
- Shared contract test suites: one `Registry` contract run against both
  backends, one `BlobStore` contract run against local and S3.
- `registry.identifiers.validate_identifier`, `registry.errors`,
  `hashing.canonical_manifest_bytes`.

### Changed (behavior)

- **`LocalRegistry`: first registration wins for digest lookups.**
  Previously a later registration of identical bytes under another name
  silently repointed the digest index -- a name-confusion vector.
- **Stricter identifiers** for `model_id`/`version` on every backend:
  <= 200 chars, no control characters, no leading/trailing whitespace,
  NFC-normalized, no path separators. Existing local registries holding
  identifiers outside these rules can no longer be read.
- `RegistryRecord.artifact_digest` must match `sha256:<64 lowercase hex>`.
- `resolve` and `revoke` now report backend errors cleanly (exit 1)
  instead of raising a traceback.
- `DuplicateRegistrationError` moved to `modelguard.registry.errors`
  (still importable from `modelguard.registry` and `...registry.local`).

### Fixed

- S3 answers `HEAD` on a missing bucket with a bodiless 404; a
  misspelled bucket is now reported as "bucket not found" rather than
  as an empty store.

### Not done

- Provenance and audit logs remain local and single-writer.
- No connection pooling; no HTTP service.
- Not tested against AWS or MinIO (moto only); see `docs/limitations.md`.

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
