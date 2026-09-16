# Changelog

All notable changes to this project are documented here. This project
follows semantic versioning once it reaches 1.0; pre-1.0 minor versions
may include breaking changes, which will be called out explicitly.

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
