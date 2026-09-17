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

## Explicitly NOT implemented yet

- **Only five policy rules exist**, and all of them evaluate boolean
  signals ModelGuard can already compute (signature validity, ML-BOM
  presence, declared lineage presence, declared license presence,
  revocation). The rules described in the product document that
  depend on data ModelGuard does not yet produce -- `max_critical_vulnerabilities`,
  `max_high_vulnerabilities` (needs scanners), `require_human_approval_for_high_risk`
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
- **The policy engine does not yet integrate with scanners or the
  registry beyond revocation** -- `reject_revoked_models` is the only
  rule connected to Phase 2's registry.
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
- **No scanners.** No unsafe-serialization detection, no dependency
  scanning, no secret scanning. A `.pkl` file is hashed and signed
  exactly like any other file; ModelGuard does not yet warn about it.
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
