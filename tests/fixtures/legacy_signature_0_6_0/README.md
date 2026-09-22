# Legacy signature fixture (ModelGuard 0.6.0)

`model.sig.json` and `model.bom.json` were produced by the **unmodified 0.6.0
signer** (commit 8984493) before any Phase 7 change, so tests can prove that
signatures written by old releases still verify.

The signing key is derived from a fixed, public string. It is a throwaway test
key and must never be trusted for anything. Do not regenerate these files with
current code: that would defeat their purpose.
