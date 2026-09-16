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

## Explicitly NOT implemented yet

- **No policy engine.** There is no allow/warn/review/deny/quarantine
  decision logic yet, only a binary signature+digest+ML-BOM check.
  `VerificationResult.allowed` reflects that narrow check only.
- **No registry.** Nothing is published, searched, or resolved by
  digest from a shared service. Everything is local files.
- **No PostgreSQL or S3 adapters.** No database, no object storage.
- **No provenance graph or lineage queries** (`guard.lineage(...)`,
  `guard.parents(...)`, etc. do not exist yet).
- **No scanners.** No unsafe-serialization detection, no dependency
  scanning, no secret scanning. A `.pkl` file is hashed and signed
  exactly like any other file; ModelGuard does not yet warn about it.
- **No revocation.** A signature that verified once will verify again
  even if the signer's key should no longer be trusted. There is no
  trust-root or revocation list yet.
- **No Sigstore, KMS, HSM, or enterprise identity integration.** Only
  raw local Ed25519 keys, generated and stored unencrypted on disk.
- **No format-specific parsing.** ModelGuard hashes bytes; it does not
  yet parse SafeTensors headers, ONNX graphs, or Hugging Face
  `config.json` semantics. Any file or directory can be hashed, but no
  format-aware metadata extraction happens automatically.
- **No async API**, no verification caching, no CI/CD templates, no
  Docker/Kubernetes integration, no audit log persistence.
- **No multi-file archive extraction** (zip, tar). Only plain files
  and directories already present on disk.

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
