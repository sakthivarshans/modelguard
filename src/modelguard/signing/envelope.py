"""The signed payload that binds an artifact digest to its ML-BOM and
signer identity.

Security rule (see architecture doc section 7.4): the signature MUST
cover the exact information a verifier relies on. This module signs a
single canonical JSON payload containing the artifact digest, the
ML-BOM digest, model identity fields, and signer/timing metadata --
never just a filename or a mutable reference.
"""

from __future__ import annotations

import json

from pydantic import BaseModel, ConfigDict

SIGNATURE_SCHEMA_VERSION = "1"
SIGNATURE_TYPE_ED25519_LOCAL = "ed25519-local"


class SignaturePayload(BaseModel):
    """The exact fields that are signed. Immutable once constructed."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = SIGNATURE_SCHEMA_VERSION
    artifact_digest: str  # "sha256:<hex>"
    mbom_digest: str  # "sha256:<hex>"
    model_id: str | None = None
    version: str | None = None
    signer_identity: str
    signed_at: str  # ISO-8601 UTC timestamp

    def canonical_json(self) -> bytes:
        data = self.model_dump(mode="json", exclude_none=True)
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


class SignatureEnvelope(BaseModel):
    """A ``SignaturePayload`` plus its detached Ed25519 signature.

    This is what gets written to a ``.modelguard.sig.json`` file next
    to a signed artifact/manifest/ML-BOM.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    signature_type: str = SIGNATURE_TYPE_ED25519_LOCAL
    payload: SignaturePayload
    signature: str  # hex-encoded raw Ed25519 signature bytes
    public_key: str  # hex-encoded raw 32-byte Ed25519 public key

    def to_json(self, *, indent: int | None = 2) -> str:
        return self.model_dump_json(indent=indent)
