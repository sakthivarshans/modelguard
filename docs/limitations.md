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

## Explicitly NOT implemented yet

- **No policy engine.** There is no allow/warn/review/deny/quarantine
  decision logic yet, only a binary signature+digest+ML-BOM check plus
  Phase 2's revocation check. `VerificationResult.allowed` does not yet
  reflect scanner findings, license rules, or organizational policy.
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
