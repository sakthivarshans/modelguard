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


