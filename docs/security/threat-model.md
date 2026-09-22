# Threat Model -- Phase 1 (Local Core)

This document covers only what Phase 1 actually implements: local
hashing, manifests, ML-BOM generation, and Ed25519 signing/verification.
The full-project threat model (registry, policy engine, scanners,
enterprise signing) is out of scope until those components exist.

## Assets in scope

- The model artifact (file or directory) being hashed and signed.
- The canonical manifest and ML-BOM documents.
- The local Ed25519 private key.
- The signature envelope (`*.sig.json`).

## Threats and how Phase 1 addresses them

| Threat | Mitigation in this release | Residual risk |
| --- | --- | --- |
| Artifact modified after signing | Digest recomputed and compared on every `verify`; any change is detected (`DigestMismatchError`). | None within scope: this is the core guarantee and it is tested (`tests/security/test_tamper_detection.py`). |
| Signature or payload bytes tampered | Ed25519 signature verification over the exact canonical payload bytes. | None within scope, given the private key was not compromised. |
| Path traversal via a malicious archive/directory | Every file path is resolved and checked against the artifact root; anything outside is rejected. Symlinks are rejected outright. | If a future release adds archive extraction, that code path needs its own traversal tests -- it is not covered yet because it doesn't exist yet. |
| Unsafe deserialization (e.g. a malicious `.pkl`) | **Not mitigated.** Phase 1 hashes bytes; it never loads, imports, or executes the artifact's contents. This means malicious pickle files are *not detected* -- but they are also never executed by ModelGuard itself, because nothing is deserialized. | A scanner that specifically flags pickle-based formats is planned for Phase 3 (Security Scanning) and is not yet implemented. Do not treat an absence-of-warning as a safety claim. |
| Untrusted signer accepted as valid | **Not mitigated.** `verify()` checks that *a* valid signature exists, matching the embedded public key, but does not check that public key against any trust root or allowlist. | This is the most important gap to close before Phase 1 code is used for anything beyond local experimentation. See `docs/limitations.md`. |
| Private key leaked via logs | No code path in this release logs the private key material. Key bytes are only ever read into memory to sign and are not echoed. | Not independently audited with a secret-scanning tool yet. |
| Private key leaked via filesystem permissions | Written with `0600` from the moment of creation (no chmod-after-write race). | The *directory* containing the key is not hardened; a misconfigured shared directory could still expose it. Caller's responsibility in Phase 1. |
| Replay of an old, still-valid signature against a newer, legitimately different artifact | The signature is bound to a specific artifact digest, so a valid signature for artifact A will correctly fail verification against artifact B (different digest). | Revocation of a signature that is still cryptographically valid (e.g. "this version was pulled") is not implemented. |
| Denial of service via extremely large artifacts | Files are hashed with 1 MiB streaming reads rather than loaded whole into memory. | No timeout or size limit is enforced yet; an attacker who can supply an arbitrarily large local path could still consume significant CPU/time. |

## Explicit non-goals of Phase 1

Consistent with the project's threat model: ModelGuard's Phase 1
signature check proves **integrity** (the artifact matches what was
signed) and **a form of authenticity** (some Ed25519 key signed it).
It proves nothing about:

- Whether the model is safe, unbiased, or free of backdoors.
- Whether the signer is who they claim to be (no identity provider is
  wired in yet).
- Whether the declared metadata (license, dataset references, parent
  model) is true -- it is recorded as `DECLARED` evidence precisely
  because it is unverified.

## Addendum -- Phase 2 (Local Registry and Provenance)

Phase 2 adds a local, file-backed registry, a hash-chained provenance
store, and a hash-chained audit log. This addendum covers only what
changed; everything above still applies unmodified.

| Threat | Mitigation in this release | Residual risk |
| --- | --- | --- |
| A model_id/version silently repointed to a different artifact ("namespace confusion") | `LocalRegistry.register` rejects re-registration of an existing model_id/version outright (`DuplicateRegistrationError`). A new artifact requires a new version string. | None within scope; tested in `tests/unit/test_registry.py::test_duplicate_registration_is_rejected`. |
| Path traversal via a malicious `model_id` or `version` string (e.g. `../../etc/passwd`) | Every identifier is validated before use as a filesystem path segment; traversal characters and separators are rejected. | Tested directly (`test_path_traversal_in_*_is_rejected`). |
| A revoked model still verifying successfully | `ModelGuard.verify()` checks the registry's revocation state for the artifact's declared model_id/version whenever a `storage_root` is configured, and denies even a cryptographically valid signature. | Only applies when the caller configures `storage_root` and the artifact was registered with the same identity the verifier looks up. A caller that never registers a model, or that checks a different model_id, gets no revocation protection -- this is a scoping choice, not a bug, but it means revocation is opt-in, not automatic. |
| Provenance or audit log tampered with after the fact | Every record is hash-chained (see `modelguard.audit.chain`); editing, reordering, or deleting a record from the middle of the log breaks the chain and is detected by `verify_chain()`. | **Not automatically checked.** Nothing in Phase 2 calls `verify_chain()` on every read for performance and simplicity reasons -- a caller must explicitly call `registry.verify()` / `provenance_store.verify()` / `audit_log.verify()` to detect tampering. A future release should decide whether to verify on every read by default (trading a small performance cost for automatic tamper detection) or keep it opt-in with clearer documentation. Flagged here as the most important gap to close before Phase 2 code is trusted for anything beyond local experimentation. |
| Deletion of the most recent record(s) from a hash-chained log | Not detected. The chain only links backward; truncating the tail leaves a self-consistent, shorter chain. | Documented in `docs/limitations.md`. Closing this requires an external checkpoint (e.g. a periodically published Merkle root) that the local log cannot forge; not implemented. |
| Concurrent writers corrupting the registry or provenance/audit logs | Not mitigated. `LocalRegistry` and the JSONL append operations assume a single writer. | A multi-writer deployment must wait for the PostgreSQL-backed adapter (later phase), which can use real transactions/locking. Do not point multiple concurrent processes at the same `storage_root` in production-like use. |
| An attacker with local write access to `storage_root` forges a whole new self-consistent chain | Not mitigated -- see the corresponding limitation in the base hash-chain design above. | Out of scope for a purely local, no-external-trust-root implementation. |

## Addendum -- Phase 3 (Policy Engine)

Phase 3 adds YAML policy-as-code loading and deterministic evaluation.

| Threat | Mitigation in this release | Residual risk |
| --- | --- | --- |
| Arbitrary code execution via a malicious policy YAML file (the classic `yaml.load()` vector) | `modelguard.policy.loader` uses `yaml.safe_load` exclusively, never `yaml.load` or `yaml.unsafe_load`. Tested directly (`test_yaml_tag_object_construction_is_rejected`). | None within scope for this specific vector. |
| A policy file silently doing nothing because of a typo'd or unrecognized rule name | Every rule name in a policy's `rules:` section is checked against a fixed known-rules set at load time; an unrecognized name raises `UnknownRuleError` rather than being accepted and ignored. | A rule that ModelGuard *does* recognize but the policy author configured incorrectly (e.g. `enabled: false` by mistake) is not detected -- that is a policy-authoring error, not a loading error, and is out of scope for schema validation. |
| A policy author accidentally (or an attacker deliberately) configuring `reject_revoked_models` to only warn, letting a revoked model through | `reject_revoked_models` ignores its configured `on_fail` value entirely and always escalates to `REVOKED` in the engine. Tested (`test_revocation_always_escalates_to_revoked_regardless_of_on_fail`). | This hardcodes a security-relevant override into engine code rather than the policy schema; if a legitimate future use case needs revocation to be genuinely soft in some environment, that will require an explicit, deliberate schema change and a new test, not a config toggle. |
| A policy with multiple failing rules being resolved using the wrong (least severe) outcome | The engine takes the maximum-severity triggered decision across all failed rules, never the first or the least severe. Tested (`test_overall_decision_is_the_most_severe_triggered`). | None within scope. |
| Non-deterministic evaluation (same inputs, different outputs across runs) | `evaluate()` is a pure function with no I/O, randomness, or wall-clock dependence in its decision logic (only the result's `evaluation_id`/`timestamp` metadata vary run to run, never the `decision` itself). Tested directly. | None within scope. |
| Extra/unexpected fields in a policy file being silently accepted, masking a typo or a downgrade attempt | Every model in `modelguard.policy.models` uses `extra="forbid"`, and the loader additionally checks for unknown top-level and `policy:`-section fields before Pydantic validation runs. | None within scope; tested (`test_unknown_top_level_field_is_ignored_gracefully`, despite its now-slightly-misleading name -- it actually asserts the field is rejected, not ignored). |
| A policy claims to gate on a security property ModelGuard cannot actually evaluate yet (e.g. vulnerability counts) | The schema simply does not accept such rule names -- see `docs/limitations.md`. A policy author cannot configure a rule that silently always passes because nothing evaluates it. | If a future phase adds a rule name to `KNOWN_RULE_NAMES` before its check function is wired into `_RULE_CHECKS`, that would be a real bug (`KeyError` at evaluation time, not a silent pass) -- covered implicitly by every engine test exercising every known rule name, but worth calling out as a regression risk for future contributors. |

## Addendum -- Phase 4 (Scanning)

Phase 4 adds a plugin-based scanner architecture (`modelguard.scanning`)
and two policy rules (`max_critical_findings`, `max_high_findings`)
that consume scan results. This addendum covers only what changed;
everything above still applies unmodified.

| Threat | Mitigation in this release | Residual risk |
| --- | --- | --- |
| A malicious pickle-based file (`.pkl`, `.pt`, `.ckpt`, etc.) executing arbitrary code the moment ModelGuard inspects it | Scanners never deserialize artifact content -- `UnsafeSerializationScanner` only checks file extensions and the first 8 bytes for a pickle protocol header. Tested directly with a crafted `__reduce__` payload that would leave a filesystem marker if it were ever unpickled (`tests/security/test_scanning_security.py::test_run_scanners_never_unpickles_a_hostile_payload`, and the equivalent in `tests/unit/test_scanning.py`). | Detection is format-level only: a pickle protocol 0/1 stream (no `PROTO` opcode) is not detected by the header sniff, and a file whose true format was disguised in some other way could still be missed. This is a detection gap, not an execution risk -- ModelGuard still never runs the payload. See `docs/limitations.md`. |
| Secrets (cloud credentials, private keys) accidentally packaged inside a model artifact | `SecretScanner` matches a narrow, high-confidence pattern set (AWS access key IDs, PEM private key headers, GitHub PATs, Slack tokens) and reports only the pattern name as evidence -- never the matched text -- so a finding cannot itself become a secret leak via logs or CI output. Tested (`test_aws_key_pattern_is_flagged_critical` and siblings assert the raw secret never appears in `evidence` or `message`). | This is intentionally a narrow scanner, not a general-purpose one (no entropy analysis, no broader credential-shape coverage) -- see `docs/limitations.md`. A secret that doesn't match one of the four patterns is not detected. |
| A scanner itself being buggy or compromised, and silently reporting "clean" instead of failing visibly | `run_scanners()` isolates every scanner in its own `try`/`except`; a raising scanner is recorded with `scanner_statuses[name]="error"` and its message in `scanner_errors`, never folded into "zero findings". `ScanReport.clean` requires `all_scanners_ok` in addition to zero findings, so an errored scanner cannot make a report look clean. Tested (`test_a_raising_scanner_is_isolated_and_does_not_abort_the_run`, `test_a_buggy_or_compromised_scanner_cannot_silently_report_clean`). | The policy engine still trusts whatever finding *counts* a caller passes into `build_context()` -- if a caller computed those counts from a source other than a real `ScanReport`, the fail-closed check on `scan_performed` would not catch that. `ModelGuard.check_policy()` closes this by always deriving the counts from its own `scan()` call. |
| Symlink-based scan evasion: an artifact directory contains a symlink to a file outside the artifact root (a host secret, another tenant's model, or a huge device file for a DoS) | The shared `iter_scannable_files()` walker never follows symlinks -- for files, directories, and the artifact root itself. Unlike hashing (which fails closed and raises `UnsafePathError`), scanning skips the symlink and reports a LOW-severity `scan_skipped` finding so the rest of the artifact still gets scanned. Tested (`test_symlink_outside_artifact_root_is_reported_not_followed`, `test_symlinked_directory_is_not_descended_into`, and the equivalent path-resolution check for a symlink that resolves outside the root even without an obvious `..` in its path). | A scan report with `scan_skipped` findings still needs a human or downstream policy to notice and investigate them -- nothing currently escalates "many symlinks were skipped" to a higher-severity signal on its own. |
| Enabling `max_critical_findings`/`max_high_findings` without ever actually running a scan, letting an artifact through on the mistaken assumption that "no findings" means "clean" | Both rules check `PolicyEvaluationContext.scan_performed` first and **fail closed** (`DENY`, or whatever `on_fail` is configured) if it is `False`, rather than treating an absent scan as zero findings. `ModelGuard.check_policy()` always runs a scan and sets `scan_performed=True`, so this only matters for callers using `modelguard.policy.evaluate()` directly with a hand-built context. Tested (`test_max_critical_findings_enabled_but_no_scan_fails_closed`, `test_max_high_findings_enabled_but_no_scan_fails_closed`). | A caller could still construct a `PolicyEvaluationContext` by hand with `scan_performed=True` and fabricated counts that don't correspond to any real `ScanReport` -- the engine has no way to verify a context's provenance, only its internal consistency. This is a known trust boundary: `build_context()`/`check_policy()` are the trusted path; direct `evaluate()` calls are the caller's responsibility. |
| Denial of service via an extremely large or deeply nested artifact during scanning | `SecretScanner` skips any file over 2 MiB before reading it. `UnsafeSerializationScanner` reads only the first 8 bytes of each file for the header sniff (the extension check reads no bytes at all). | No overall time budget or total-artifact-size limit is enforced across a whole scan; a directory with an extremely large number of small files could still make a scan slow. Not load-tested. |

## Explicit non-goals of Phase 4

Consistent with the project's threat model: scanning proves that
ModelGuard *looked* for a specific, narrow set of known-risky patterns
and either found them or didn't. It proves nothing about:

- Whether a model file free of the three built-in scanners' findings
  is actually safe to load -- only that these specific checks did not
  fire.
- Whether a dependency, container, or license is acceptable (no
  dependency/container/license scanners exist yet).
- Whether the model's runtime *behavior* is safe (data poisoning,
  behavioral backdoors, trigger-based misbehavior are all explicitly
  out of scope for static scanning, consistent with `01-project-overview.md`'s
  distinction between integrity/authenticity/provenance/policy
  compliance and behavioral safety).

## Addendum -- Phase 5 (CI/CD, caching, admission, trust roots)

Phase 5 adds trust roots, an integrity gate, a digest cache, an
admission hook, and CI/Docker examples. It also corrects a defect in
earlier addenda: the Phase 3 table said policy evaluation had "no
residual risk" for the tested cases, but no test covered a *tampered
artifact passing through `check_policy`*, and one test encoded the
wrong result. Everything above still applies unless noted here.

| Threat | Mitigation in this release | Residual risk |
| --- | --- | --- |
| **(Defect in 0.3.0/0.4.0)** Tampered artifact receives `ALLOW` from `policy check` because policy only saw `signature_valid` | Unconditional `artifact_integrity` DENY on digest mismatch, outside the rule set so no policy can weaken it. Tests: `test_check_policy_reflects_tampered_artifact_as_denial`, `test_tampered_artifact_is_denied_even_by_an_empty_policy`, CLI regression `test_policy_check_denies_a_tampered_artifact_regression`. | Direct `evaluate()` callers that hand-build a context with `artifact_digest_matches=None` skip the gate (compat). Anyone who relied on 0.3.0/0.4.0 `policy check` for tamper detection had no such protection. |
| Attacker re-signs a tampered model with their own key ("signature confusion", previously listed as unmitigated) | Trusted key fingerprints checked against the key that verified the signature; `require_trusted_signer`; `admit()` requires a trusted signer regardless of policy. Test: `test_attacker_resigning_with_own_key_is_denied`. | **Opt-in on `verify`/`policy check`**: with no fingerprints, any valid signature passes and the result says `signer_trusted=None`. Fingerprint provenance is the caller's problem. `signer_identity` remains an unverified claim. No expiry or key-revocation mechanism besides removing the fingerprint. |
| CI attacker edits the trusted fingerprint or policy inside the same pull request | Example workflow reads the fingerprint from a repository *variable* and the policy from the PR *base* commit, uses `pull_request` (never `pull_request_target`), and `contents: read`. | Static checks only; a team that copies the example and moves the fingerprint/policy into the PR-controlled tree loses this. Workflow untested on a real runner. Actions tag-pinned, not SHA-pinned. Compromise of the ModelGuard revision or of repository-variable write access is out of scope. |
| Stale cache lets a revoked model through | Cache holds only the digest computation; revocation, signature, trust and policy are recomputed every call. Test: `test_cached_verification_never_overrides_a_new_revocation`. | None specific to caching. (Revocation itself remains opt-in; see limitations.) |
| Cache returns an old digest for modified files | Metadata fingerprint incl. `ctime` (not settable by unprivileged code) and inode; racy-timestamp margin; stat-hash-stat; strict schema; per-entry consistency check; symlinks/non-regular files/inode 0 bypass the cache. Tests incl. mtime-restoration and same-size edits (mutation-checked). | **Trusts the filesystem.** Defeated by root, raw device writes, clock manipulation; `mmap` writes may lag timestamps; stale attributes on network/FUSE mounts; unsupported off POSIX. Documented in `docs/limitations.md`. Off by default. |
| Local attacker poisons the cache file | Cache file rejected if a symlink, not owned by the current user, group/world-writable, oversized, or corrupt/schema-mismatched; written `0600` via atomic rename; entry count bounded. | The **same user** (or root) can forge a self-consistent entry; nothing authenticates the cache file. Do not place it where the artifact supplier can write. |
| Cache growth / corrupt cache as denial of service | 16 MiB file limit, 128-entry cap, any error is a miss, write failures are logged and swallowed. | A very large number of artifacts churning through 128 slots reduces hit rate (performance only). |
| Admission gate bypassed by a crash, misconfiguration, or an unauditable environment | `admit()` fails closed on: no trust roots, *any* exception, and audit-write failure; requires digest match + trusted signer + allowed decision independent of policy. Tests for each path. | `admit()` is advisory: callers can ignore it. Audit log is single-writer and tail-truncation-blind. Catching `Exception` broadly means a programming bug appears as a denial (surfaced in `reasons`/`error`), which is the intended trade-off. |
| Check-to-use race: files change between verification and model load | None in code. Documented; example Dockerfile uses root-owned read-only files and non-root user, and its header shows `docker run --read-only`. | **Open.** Any writable path between check and load defeats verification. Also applies to the (unchanged) window between the hash and the scanners' reads inside one `check_policy`. |
| Misleading "verified" metadata on container images | The Docker example makes **no** verification-status label; id/digest labels are documented as informational. Startup verification is the control. | Consumers may still over-trust labels regardless of documentation. |
| Redundant double hashing enlarging the tamper window inside `check_policy` | The scan now reuses the digest computed by `verify()`. Test: `test_check_policy_hashes_the_artifact_only_once`. | The window between hashing and the scanners' reads remains (see above). |

## Explicit non-goals of Phase 5

Trust roots prove "a key I listed signed these bytes". They do not prove
the signer is honest or uncompromised, that the model is safe, or that
the signer's identity string is truthful. Admission proves the checks
passed at one moment on one host; it does not sandbox, monitor, or
constrain the model afterwards.

## Addendum -- Phase 6 (PostgreSQL registry, object storage)

New trust boundaries: the registry database and the object store are
**untrusted for integrity of artifact bytes** (digest-verified on every
read) and **trusted only for revocation availability and freshness**.

| Threat | Mitigation | Residual risk |
| --- | --- | --- |
| Registry outage or timeout read as "not revoked" (fail-open) | `RegistryBackendError` on any backend fault; `verify` propagates, `admit()` denies, CLI exits 1. Tests: outage through SDK, admission and CLI. | Availability of revocation checks depends on the database. |
| Silent fallback from PostgreSQL to the local registry | `--registry-dsn-env` with an unset/empty variable is an error; nothing is written locally. Test: `test_unset_dsn_env_is_an_error_not_a_fallback_to_local`. | Operator omits the flag entirely and gets the local registry (or no revocation check). |
| DSN or credential disclosure | DSN never in argv (env-var name), `repr`, or exceptions; provider/driver text reduced to a category. Tests assert secrets absent. | Process environment and core dumps are outside scope. |
| Man-in-the-middle forges revocation answers | Non-local hosts require `sslmode=verify-full`/`verify-ca`; explicit host required. | `allow_insecure_transport=True` exists for tests; misuse in production is possible. |
| Rewriting registrations or revocations | DB-enforced append-only triggers; UNIQUE(model_id, version); hash-chained revocation events serialized by advisory lock; runtime role limited to SELECT/INSERT. Tests incl. owner-level attempts and concurrent writers. | Owners/superusers can disable triggers; newest-event deletion undetected; records unsigned. |
| Tampered or substituted schema/migrations | Checksummed migrations; refuse checksum mismatch and newer-than-code schemas. | An owner can rewrite both schema and checksums. |
| Forged or corrupted registry rows | Strict validation; row content cross-checked against indexed columns. | A privileged user can swap in a different *valid* record. |
| SQL injection via identifiers or fields | Parameterized queries only; shared identifier validation; test with SQL metacharacters. | None known; never build SQL with string formatting (the only formatted SQL is in test fixtures). |
| Look-alike names / digest re-pointing | NFC + whitespace/control/path rules; first registration wins for digest resolution (both backends). | Cross-script confusables not blocked. |
| Tampered or swapped objects in S3 | Every read streamed through SHA-256 against its content address before being kept; size limits enforced while streaming. Tests: tampered blobs, tampered manifests, on local and S3. | Same-digest overwrite denies service. |
| Path traversal / hostile manifest signed by a malicious publisher | Manifest validated after its hash matches: absolute, `..`, backslash, control, empty/`.` segments, duplicates, file-vs-directory conflicts, non-canonical bytes, wrong sizes, count/size limits all refused; staged in a private directory; no symlinks created; failure removes only staging. | Case-insensitive filesystems can merge paths; Windows untested. |
| Exfiltration by symlink swap during upload | `O_NOFOLLOW` + `fstat` on the opened descriptor; content re-hashed while uploading and discarded on mismatch. | A read-only window remains between open and hash-check for files the caller can already read. |
| Plaintext object-store traffic or credentials in URLs | Non-https non-loopback endpoints and userinfo in URLs refused; credentials only via the AWS chain or an injected client. | `allow_insecure_transport=True` for tests. |
| Misspelled/missing bucket hidden as empty store | One-time `head_bucket` probe on first miss; 403 never reported as absence. | Without HeadBucket/ListBucket permission the distinction can be lost. |

Non-goals: ModelGuard does not sandbox the database or bucket, manage
their encryption at rest, or authenticate registry *contents* (only the
artifact signature does that).

## Addendum -- Phase 7 slice 7a (signature-scheme plumbing)

New trust boundary: **which cryptographic scheme verifies a given
signature is no longer read from an unsigned field alone.** For a
format-version-2 payload, the algorithm and the signing key's
fingerprint are inside the signed bytes; the unsigned
`signature_type` label is checked for agreement but never trusted on
its own.

| Threat | Mitigation | Residual risk |
| --- | --- | --- |
| Algorithm confusion: relabel `signature_type` to imply a different scheme was used | For v2 payloads, `signature_algorithm` is signed; the unsigned label must equal it or verification fails (`SignatureInvalidError`). For v1, the single legal label is a fixed constant, not attacker input. Tests: relabeling in both directions; mutation-checked (test fails when either check is removed). | A verifier that only ever calls `check_signature_bytes`/`verify_envelope_signature` without a trust check still only proves "some registered-scheme key produced this", same as before. |
| Key substitution: swap the embedded public key for a different one whose signature also happens to verify | v2 payloads sign `key_id` (fingerprint of the intended key); the verifier recomputes the fingerprint from the actual key bytes and compares. Test: swap key+signature for a second valid keypair, confirm rejection quoting "key was substituted". Mutation-checked. | v1 payloads have no `key_id`; substitution there is caught only by the outer trust-fingerprint check (which was already the only defense pre-0.7.0), not by the signature itself. |
| Downgrade: present a strong-scheme key/signature under a weaker/legacy envelope shape to dodge a stricter check | v1 requires the fixed `ed25519-local` label and enforces `ed25519` regardless of what bytes are supplied; a P-256 key/signature under that label fails on the cryptographic check itself, not on a scheme check that could be skipped. Test: `test_a_v1_shaped_signature_cannot_claim_to_be_a_stronger_scheme`. | No downgrade *within* v2 is possible (algorithm is signed); the only "downgrade" surface is choosing to accept v1 at all, which is why `allow_legacy_v1`/`--reject-legacy-signatures` exists as an explicit opt-out. |
| Hostile signature file (oversized, deeply nested, non-UTF-8, unknown fields) consumes resources or reaches a parser bug | `load_envelope()` caps bytes read before JSON parsing, decodes strict UTF-8, and validates against a schema that rejects unknown fields at every level; failures are normalized to `MalformedSignatureError` without echoing attacker-controlled values. Tests: oversized file, deep nesting, non-UTF-8, unknown top-level and nested fields. | A parser resource-exhaustion bug in the JSON decoder itself, below the byte cap, is out of scope (stdlib `json`). |
| Signing provider (future KMS/HSM adapter) leaks credentials or resource identifiers through exception text | `sign_with_provider()` converts any provider exception to `SigningProviderError` carrying only `type(exc).__name__`, with the original exception's `__cause__` suppressed. An adapter that wants a specific, safe message raises `SigningProviderError` itself. Test: a provider whose exception text contains a fake secret token; asserts the token never appears in the raised error and `__cause__` is `None`. | An adapter author who raises a bare, unwrapped exception with sensitive text, bypassing `SigningProviderError`, defeats this; the contract is enforced by tests on the built-in call path, not by construction. |
| A misconfigured or compromised signing provider returns a signature that does not match its own reported public key (e.g. a KMS alias silently repointed at a different key) | `sign_with_provider()` verifies the envelope it just built, against the provider's own `public_key()`, before returning it; a mismatch raises `SigningProviderError` and no envelope is produced. Test: provider whose `sign()` uses a different key than `public_key()` reports. | Only catches the mismatch at signing time; if the alias is repointed *after* signing, that is a trust-root/rotation problem for slice 7b, not this check. |

## Explicit non-goals of Phase 7 slice 7a

This slice does not add a trust-configuration format, key expiry,
per-key revocation, key rotation tooling, KMS/HSM adapters, or
Sigstore support -- see `docs/limitations.md` and the Phase 7 plan.
Binding `signature_algorithm`/`key_id` into the signed payload makes
those *representable* in a future trust config; it does not itself
change how trust is decided (still a flat fingerprint set).
