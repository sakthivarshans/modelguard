# Known Limitations (Phase 1)

This document exists so nobody has to guess what "ModelGuard v0.1" does
and does not do. If a capability is not listed under "Implemented", do
not assume it works.

## Implemented in this release

- Deterministic SHA-256 hashing of a single file or a directory tree,
  with documented, tested rules (see `src/modelguard/hashing/digest.py`).
- Canonical, versioned manifest generation.
- A minimal, CycloneDX-envelope-shaped ML-BOM with per-field evidence
  levels (`DECLARED`, `SIGNED`, `VERIFIED`, `INDEPENDENTLY_TESTED`,
  `HUMAN_APPROVED`). Only `DECLARED` values are produced automatically
  in Phase 1 -- nothing is auto-promoted to a stronger evidence level.
- Local Ed25519 signing and verification, with a signature payload
  that binds the artifact digest, the ML-BOM digest, declared model
  identity, signer identity, and signing time.
- Tamper detection: a modified file, a renamed file, or an added/removed
  file inside a directory artifact all change the digest and are
  detected as a mismatch at verification time.
- A CLI (`modelguard inspect/manifest/mbom/keygen/sign/verify`) with
  JSON output and CI-friendly exit codes.
- A Python SDK (`modelguard.ModelGuard`) exposing the same operations.
- **(Phase 2)** A local, file-backed **registry**: register a
  manifest+ML-BOM under `model_id`/`version`, resolve by name or by
  digest, list versions, and **revoke**/unrevoke a version (revocation
  history is preserved). Re-registering an existing `model_id`/`version`
  is rejected outright rather than silently overwritten.
- **(Phase 2)** A local **provenance store** recording lineage edges
  (`FINE_TUNED_FROM`, `QUANTIZED_FROM`, `DEPLOYED_TO`, etc.) and graph
  queries: `parents`, `children`, `lineage`, `find_models_derived_from`,
  `find_deployments_using_revoked_model`.
- **(Phase 2)** A hash-chained, tamper-evident **audit log** primitive
  (`modelguard.audit`), used by both the registry's revocation history
  and the provenance store, plus a general-purpose `LocalAuditLog`.
- **(Phase 2)** `verify()` is now **revocation-aware**: if a
  `storage_root` is configured and the verified artifact's
  `model_id`/`version` is revoked in the registry, verification is
  denied even though the signature and digest are still valid.
- **(Phase 2)** CLI: `modelguard register/resolve/revoke/lineage/provenance record`,
  and `modelguard verify --storage-root ...` for revocation-aware verification.
- **(Phase 3)** A **policy engine** (`modelguard.policy`): YAML policy
  documents loaded with `yaml.safe_load` and validated against a
  strict schema (unknown top-level fields, unknown "policy:" fields,
  and unknown rule names are all rejected, not silently ignored).
  Five rules are implemented: `require_valid_signature`,
  `require_ml_bom`, `require_known_lineage`, `require_license`,
  `reject_revoked_models`. Each rule's failure maps to a configurable
  `on_fail` action (`warn`/`review`/`quarantine`/`deny`); the overall
  decision is the most severe triggered outcome
  (`ALLOW`/`ALLOW_WITH_WARNINGS`/`REVIEW_REQUIRED`/`QUARANTINE`/`DENY`/`REVOKED`).
  `reject_revoked_models` always escalates to `REVOKED` regardless of
  its configured `on_fail`, since a revoked model must never be merely
  a warning. Evaluation is a pure, deterministic function of a small
  boolean context -- the same inputs always produce the same decision.
- **(Phase 3)** SDK: `ModelGuard.check_policy(...)` runs `verify()`
  and evaluates a policy against the result in one call.
- **(Phase 3)** CLI: `modelguard policy validate` / `modelguard policy check`,
  with distinct exit codes per decision (0 allowed, 2 deny,
  3 review required, 4 quarantine, 5 revoked, 1 error).
- **(Phase 4)** A plugin-based **scanner architecture** (`modelguard.scanning`):
  a `Scanner` `Protocol`, a shared symlink-safe file-walking helper, and
  three built-in scanners --
  `UnsafeSerializationScanner` (pickle-extension and pickle-protocol-header
  detection; never unpickles anything), `SecretScanner` (a narrow,
  high-confidence regex set: AWS access key IDs, PEM private key
  headers, GitHub PATs, Slack tokens; size- and binary-file-skipping;
  never echoes matched secret text into a finding), and
  `MetadataCompletenessScanner` (informational-only: missing license,
  missing lineage, missing model identity). `run_scanners()` isolates
  each scanner so one raising scanner cannot crash the run or silently
  count as "clean" -- see `ScanReport.clean`/`all_scanners_ok`.
- **(Phase 4)** Two new policy rules that consume scan results:
  `max_critical_findings` and `max_high_findings`. Both **fail closed**:
  enabling either rule without a scan having actually run denies rather
  than silently treating "no scan" as "zero findings". `RuleConfig`
  gained a `max_count` field for these two rules.
- **(Phase 4)** `ModelGuard.scan(...)` runs the default scanner set
  against a local artifact. `ModelGuard.check_policy(...)` now always
  runs a scan as part of every policy check, so `max_critical_findings`/
  `max_high_findings` have real finding counts to evaluate without any
  extra caller-side wiring.
- **(Phase 4)** CLI: `modelguard scan PATH [--manifest ...] [--mbom ...]
  [--fail-on info|low|medium|high|critical] [--format json]`. Exit code
  0 if every scanner ran successfully and no finding at or above
  `--fail-on` (default: `high`) exists; 2 otherwise; 1 on an
  unexpected error.

## Explicitly NOT implemented yet

- **Seven policy rules exist**, and all of them evaluate signals
  ModelGuard can already compute (signature validity, ML-BOM presence,
  declared lineage presence, declared license presence, revocation,
  and -- as of Phase 4 -- CRITICAL/HIGH scan finding counts). The rules
  described in the product document that depend on data ModelGuard
  still does not produce -- `require_human_approval_for_high_risk`
  (needs risk classification), trusted-publisher allow-lists, format
  allow/block-lists, and expiration -- are **not implemented and not
  accepted** by the policy schema. A policy file referencing them is
  rejected at load time (`UnknownRuleError`) rather than silently
  accepted and ignored.
- **No policy simulation / dry-run mode** that shows what a policy
  *would* decide across a batch of historical artifacts without
  actually gating anything.
- **`require_license` and `require_known_lineage`, when reached
  through `ModelGuard.check_policy()`, only look at the ML-BOM**, not
  the original manifest -- `check_policy()` reconstructs a minimal
  Manifest from the signature payload (which does not carry the
  license field) rather than requiring the caller to also supply the
  original manifest file. Call `modelguard.policy.evaluate()` directly
  with a full `PolicyEvaluationContext` if you need manifest-level
  license data considered.
- **The policy engine does not yet integrate with the registry beyond
  revocation** -- `reject_revoked_models` is the only rule connected to
  Phase 2's registry. Scanning is now integrated (Phase 4), but risk
  classification and license allow-lists are not.
- **No PostgreSQL, S3, or FastAPI service.** Phase 2's registry and
  provenance store are local, file-backed implementations behind
  `Protocol` interfaces (`Registry`, and an implicit provenance-store
  shape) -- nothing is shared across machines or served over a
  network yet. Concurrent writers to the same `storage_root` are not
  safe (no file locking); this is a single-writer, single-machine
  implementation.
- **No provenance graph database.** `lineage`/`parents`/`children`/
  `find_models_derived_from` are in-memory traversals over the full
  event log on every call. This is fine at the scale a local file
  naturally supports; it has not been tested or optimized for large
  event counts.
- **No scanners beyond the three built-in ones.** No dependency
  scanning, no container scanning, no license-allowlist scanning, no
  opcode-level pickle analysis (only extension and header-byte
  detection -- see `src/modelguard/scanning/unsafe_serialization.py`),
  no recursive archive inspection (a `.zip`/`.tar` inside an artifact
  is scanned as an opaque binary blob, not unpacked and scanned
  internally), and no suppression/triage workflow for findings beyond
  the fixed `status="open"` field. The secret scanner is intentionally
  narrow (four pattern families) rather than general-purpose -- see
  `src/modelguard/scanning/secrets.py`.
- **No Sigstore, KMS, HSM, or enterprise identity integration.** Only
  raw local Ed25519 keys, generated and stored unencrypted on disk.
- **No format-specific parsing.** ModelGuard hashes bytes; it does not
  yet parse SafeTensors headers, ONNX graphs, or Hugging Face
  `config.json` semantics. Any file or directory can be hashed, but no
  format-aware metadata extraction happens automatically.
- **No async API**, no verification caching, no CI/CD templates, no
  Docker/Kubernetes integration.
- **No multi-file archive extraction** (zip, tar). Only plain files
  and directories already present on disk.
- **The hash-chained audit/provenance/revocation logs detect tail
  truncation only partially.** Editing, reordering, or deleting a
  record in the *middle* of a log is detected by `verify()`/
  `verify_chain()`. Deleting records from the *end* of the log is not
  detectable by the chain alone, since nothing downstream references
  the missing tail. A Merkle-checkpoint or external-timestamping
  adapter would close this gap and is not implemented.

## Security-relevant limitations to be aware of

- Local Ed25519 private keys are stored **unencrypted** on disk (mode
  `0600`). Losing control of the filesystem means losing control of
  the key. This is documented as a development-only mechanism; do not
  use `modelguard keygen` for anything you would call production.
- There is no trust-root concept yet: `modelguard verify` will accept
  *any* valid signature from *any* public key embedded in the
  signature file, as long as the signature and digests check out. It
  does not yet check "is this signer someone I trust". Wiring in an
  explicit, caller-supplied trusted-public-key check is the natural
  next security-relevant piece of work, ahead of the full policy
  engine.
- Symlinks are rejected outright rather than safely resolved. This is
  a conservative, fail-closed choice, not a statement that symlink
  support is unimportant -- see the design note in
  `src/modelguard/hashing/digest.py`.
- **(Phase 4)** Scanning treats symlinks differently from hashing on
  purpose: hashing fails closed (raises) on any symlink, because it is
  the security-critical identity computation; scanning is best-effort
  and skips a symlink with a LOW-severity `scan_skipped` finding
  instead, so one unsafe entry does not abort the rest of the scan.
  Either way, a symlink is never followed -- only what happens on
  encountering one differs. See `src/modelguard/scanning/_walk.py`.
- **(Phase 4) Scan reports are not signed.** A `ScanReport` produced by
  `modelguard scan` or `ModelGuard.scan()` is not itself cryptographically
  bound to anything beyond the artifact digest it re-hashes locally;
  it is not embedded in the signed manifest/ML-BOM/signature envelope,
  and there is no tamper-evidence on a scan report the way there is on
  the audit/provenance/registry logs. A scan report should be treated
  as a local, unsigned observation, not an attestation.
