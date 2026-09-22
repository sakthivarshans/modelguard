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
- **No FastAPI service.** Nothing is served over a network by
  ModelGuard itself. The registry can be shared across machines via the
  optional PostgreSQL adapter (Phase 6), but **provenance and audit logs
  are still local, file-backed, and single-writer** (no file locking):
  concurrent writers to the same `storage_root` are not safe. The local
  registry is likewise single-machine, single-writer.
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
- **No async API.** No Kubernetes integration (no admission webhook,
  no sidecar). See the Phase 5 section for what CI/Docker/admission
  support actually is.
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
- **Trust roots are opt-in (Phase 5).** Without
  `--trusted-fingerprint` / `trusted_key_fingerprints=`, `verify` still
  accepts a valid signature from *any* key embedded in the signature
  file -- an attacker can re-sign a tampered model with their own key
  and it verifies. `VerificationResult.signer_trusted` is `None` in
  that case and the CLI prints `Signer: NOT CHECKED`. The
  `require_trusted_signer` rule and `admit()` both fail closed when no
  trust roots are configured. See the Phase 5 section for what trust
  roots do and do not cover.
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

## Phase 5: CI/CD, caching, admission, trust roots

### Implemented

- `require_trusted_signer` policy rule and trusted key fingerprints
  (SHA-256 of the raw Ed25519 public key), on the SDK and both CLI
  commands. Multiple fingerprints may be trusted at once (the
  mechanism for rotation: add the new one, later remove the old).
- An **unconditional integrity gate**: a digest mismatch is always a
  `DENY` in policy evaluation, independent of policy content.
- Opt-in digest cache (`ModelGuard(cache_dir=...)`, `--cache-dir`).
- `modelguard.admission.admit()`, a fail-closed, optionally audited
  decision function.
- Examples: GitHub Actions workflow, Docker build+startup pattern,
  `deploy_gate.py`.

### Not implemented / limits (be aware before relying on these)

- **Trust roots are fingerprints of raw local keys.** There is no
  expiry, no per-key revocation (remove the fingerprint), no key
  rotation tooling, and no binding between the human-readable
  `signer_identity` string and the key: the identity is still an
  unverified claim. A structured trust-configuration file, expiry, and
  revocation are planned for Phase 7 slice 7b (not yet built). A
  fingerprint is only as trustworthy as the channel you obtained it
  through.
- **The digest cache trusts filesystem metadata.** A hit means "size,
  mtime, ctime, inode and device are unchanged and old enough", not "the
  bytes were re-read". It is unsound against an attacker with root, raw
  block-device access, or control of the system clock; writes through a
  shared `mmap` may not update timestamps promptly on some systems;
  network/FUSE filesystems with attribute caching and Windows (where
  `st_ctime` is creation time) are unsupported -- the cache is bypassed
  off POSIX and for inode 0, but is *not* able to detect a network
  filesystem that reports stale attributes. It defends the cache *file*
  against other local users (rejects symlinks, foreign owners, group- or
  world-writable files, oversized or corrupt content) but not against
  the same user forging a consistent entry. Keep `--cache-dir`
  somewhere the artifact's supplier cannot write. Do not enable it on
  hosts where the model directory is writable by an untrusted party
  *and* you cannot tolerate this assumption: leave it off (the default).
- **Only digest computation is cached.** Scans are re-run every time
  (they are cheap next to hashing; measured). Signature, ML-BOM,
  trust, revocation and policy are never cached.
- **Check-to-use window.** `verify`/`admit` check the artifact at one
  instant. If the files can change before the model is loaded (writable
  volume, swapped mount, attacker with write access), the check does
  not protect the load. Mitigations are deployment-level (read-only
  root filesystem, immutable image layers, verifying from the same file
  descriptors you load) and out of scope here.
- **Revocation is still opt-in.** It is consulted only when a
  `storage_root` is configured *and* the signature carries a
  `model_id`/`version`. `VerificationResult.revocation_checked` and
  `AdmissionDecision.revocation_checked` say whether it happened, but
  the `reject_revoked_models` rule itself still reports "not revoked"
  when nothing was checked -- a known imprecision in its message. A
  deploy target with no access to a registry gets no revocation
  protection; Phase 6's PostgreSQL registry (`--registry-dsn-env`) makes a
  shared registry possible, but it is still opt-in.
- **`admit()` is a function, not an enforcement point.** Nothing stops
  a caller ignoring `admitted=False`. There is no Kubernetes webhook,
  no server, no rate limiting. The admission audit log is the same
  single-writer, tail-truncation-blind JSONL chain as the other logs.
- **The CI and Docker examples are untested against real runners.** The
  workflow is validated statically (YAML parse, permissions, trust
  wiring); the Dockerfile statically; `entrypoint.sh` and
  `deploy_gate.py` are exercised behaviorally in unit tests. Nobody has
  run the workflow on GitHub or built the image in this repository's CI.
  Actions are tag-pinned (pin to SHAs yourself) and the install line
  needs a reviewed commit SHA because ModelGuard is not published to a
  package index.
- **Image labels are not evidence.** `org.modelguard.*` labels in the
  Docker example are informational claims by the image builder. There is
  no `verification.status` label on purpose.
- **In-image verification is only as strong as what the attacker can
  change.** If they can rewrite the model they can usually also rewrite
  the BOM, signature, and policy in the same writable layer. Supply the
  trusted fingerprint (and ideally the policy) from deployment
  configuration outside the image, as the example entrypoint does for
  the fingerprint.
- `policy.evaluate()` called directly with a hand-built context that
  leaves `artifact_digest_matches=None` skips the integrity gate (kept
  for compatibility with pre-0.5.0 hand-built contexts). `build_context`
  and `check_policy` always set it. Prefer them.

## Phase 6: PostgreSQL registry and object storage

See `docs/deployment/postgres.md` for setup (roles, grants, TLS).

### Implemented

- `modelguard.registry.postgres.PostgresRegistry` (extra: `postgres`),
  with versioned, checksummed migrations, database-enforced append-only
  history, a hash-chained revocation log, transport policy, and
  fail-closed errors. Identical behavior to `LocalRegistry` is enforced
  by a shared contract test suite.
- `modelguard.storage`: a content-addressed `BlobStore` protocol,
  `LocalBlobStore`, `S3BlobStore` (extra: `s3`), and
  `upload_artifact` / `download_artifact` with full re-verification.
- CLI: `--registry-dsn-env` on `verify`, `policy check`, `register`,
  `resolve`, `revoke`; `registry migrate|verify-chain`;
  `artifact push|pull`.
- `LocalRegistry` behavior changes made to unify the contract:
  first-registration-wins digest resolution, shared identifier
  validation, strict `sha256:<64 hex>` digests.

### Not implemented / limits

- **Not a service.** Each operation opens one short-lived database
  connection (no pooling). Throughput is bounded by connection setup.
- **Database owners and superusers defeat immutability.** The triggers
  and hash chain stop application bugs and stolen *application-role*
  credentials, and make edits detectable; a table owner can disable the
  triggers (the tests do exactly this to simulate the attacker). Like
  the local logs, the chain cannot detect deletion of the *newest*
  events. Use separate owner and runtime roles.
- **Provenance and audit remain local**, so the admission audit trail
  and lineage are not shared across hosts.
- **Only the registry, not artifacts, is trusted less.** The registry
  holds manifests/ML-BOMs and revocations, not model bytes; a compromised
  registry can withhold a revocation (denial of protection) even though
  it cannot forge a valid signature. Revocation freshness is only as good
  as the registry's availability and the network path to it.
- **Registry records are unauthenticated data.** Records are validated
  and cross-checked against indexed columns, but they are not signed; a
  privileged DB user can substitute a *different valid* record for a
  version. Trust for the artifact still comes from the signature, not
  the registry.
- **Identifier look-alikes across scripts** (e.g. Cyrillic vs Latin
  letters) are not blocked; only NFC normalization, control characters,
  whitespace, length and path characters are.
- **S3: integrity yes, availability and confidentiality no.** Every read
  is hash-verified, so a tampered or swapped object is refused -- but a
  same-digest overwrite with bad bytes denies service until repaired.
  Bucket policy, encryption at rest, versioning/Object Lock, and lifecycle
  rules are the deployer's job.
- **A store that is missing an object is not distinguishable from a
  bucket you cannot see**: 403 raises (never "absent"), but with
  restricted permissions a missing bucket may be reported as a missing
  blob. Grant `s3:ListBucket` so S3 returns 404 for missing keys.

## Phase 7 slice 7a: signature-scheme plumbing

### Implemented

- A signature scheme registry (`modelguard.signing.schemes`) decoupled
  from key custody: `ed25519` (unchanged) and a new
  `ecdsa-p256-sha256` (uncompressed SEC1 public key, DER
  `ECDSA-Sig-Value` signature, SHA-256). The registry is an immutable
  mapping; a caller-supplied verifier cannot replace a built-in scheme,
  only add a new algorithm id.
- A `SignerProvider` protocol (`modelguard.signing.providers`) so a
  signature can come from something other than a local private key file
  in a future slice (KMS, HSM). `LocalEd25519Signer` adapts the existing
  local key path onto it; `ModelGuard.sign()` is unchanged and still
  produces an Ed25519 signature by default. `ModelGuard.sign_with_provider()`
  is the new entry point for other providers.
- A new **format-version-2** signature payload that additionally signs
  `signature_algorithm` and `key_id` (the fingerprint of the signing
  key), so the algorithm and the key cannot be swapped after signing
  without invalidating the signature. Version 1 (pre-0.7.0) payloads are
  unchanged byte-for-byte (the new fields are omitted, not null, when
  absent) and still verify; `ModelGuard(allow_legacy_signatures=False)`
  / CLI `--reject-legacy-signatures` refuses them going forward.
  `tests/fixtures/legacy_signature_0_6_0/` holds a signature produced by
  the unmodified 0.6.0 signer, checked in as a compatibility guard.
- `verify_envelope_signature()` is now the single authoritative
  verification path (`check_signature_bytes` delegates to it) and
  returns which algorithm and key fingerprint actually verified, rather
  than the caller re-deriving the fingerprint from an unverified claim.
  `VerificationResult.signature_algorithm` /
  `.signer_key_fingerprint` expose this over the SDK and CLI.
- Signature files are parsed through a single bounded loader
  (`load_envelope`): size-capped before any JSON parsing, strict schema
  (unknown fields rejected), and a `MalformedSignatureError` distinct
  from `SignatureInvalidError` for anything that isn't even a
  well-formed envelope.
- `sign_with_provider()` re-verifies the signature it just produced,
  against the provider's own reported public key, before returning an
  envelope, and normalizes every provider exception to
  `SigningProviderError` reporting only the exception type (never the
  original message, which for a real KMS/HSM can contain credentials or
  resource identifiers).

### Not implemented / limits (be aware before relying on these)

- **No trust configuration yet.** Trust is still only a flat set of
  fingerprints (`--trusted-fingerprint`); expiry, per-key revocation,
  scoping, and binding `signer_identity` to a key are slice 7b.
- **No KMS or HSM adapter yet.** `SignerProvider` exists so one can be
  added without changing verification; none ships in this slice (7c).
- **No Sigstore adapter.** Deferred; see the Phase 7 plan.
- **Ed25519 verification does not reject small-order public keys**
  (delegated to OpenSSL via `cryptography`), so a *universal* signature
  under such a key verifies for any message without any private key.
  This has always been true of the Ed25519 path and is unchanged by
  this slice. It is harmless only because trust roots are the actual
  gate: no configuration should ever list such a key as trusted, and an
  untrusted signature was never going to be `allowed` regardless. It
  does mean `check_signature_bytes`/`verify_envelope_signature` alone
  (without a trust check) cannot be used as a proof that *some*
  legitimate signer produced a given signature.
- **ECDSA P-256 signatures are not unique.** `(r, s)` and `(r, n - s)`
  both verify for the same message and key (standard ECDSA signature
  malleability). A signature must never be treated as an identifier;
  ModelGuard never does this (the artifact digest is the identity), but
  any new code must not either.
- **`key_id` binds a key to a payload, not a key to an identity.**
  `signer_identity` remains an unverified claim; only the key
  fingerprint is checked against trust roots.
- **Downloads are private (0600/0700)** and case-insensitive filesystems
  can merge paths that differ only by case; Windows is untested.
- **Limits are defaults, not guarantees**: 256 GiB total, 100,000 files,
  64 MiB manifest. Tune per deployment.
- **Test coverage of S3 is against moto** (a real HTTP server
  implementing the S3 API), not against AWS or MinIO; PostgreSQL tests
  run against a real PostgreSQL 16 but only when
  `MODELGUARD_TEST_POSTGRES_DSN` is set (otherwise visibly skipped).
