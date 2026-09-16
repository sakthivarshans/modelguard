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
