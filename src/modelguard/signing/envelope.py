"""The signed payload that binds an artifact digest to its ML-BOM and
signer identity.

Security rule (see architecture doc section 7.4): the signature MUST
cover the exact information a verifier relies on. This module signs a
single canonical JSON payload containing the artifact digest, the
ML-BOM digest, model identity fields, and signer/timing metadata --
never just a filename or a mutable reference.

Payload format versions
-----------------------

``"1"`` (legacy, ModelGuard <= 0.6.0)
    No algorithm and no key id inside the signed bytes. The scheme is
    implied: the envelope's ``signature_type`` must be exactly
    ``"ed25519-local"``. Still verifiable; can be refused with
    ``allow_legacy_v1=False``.

``"2"``
    The signed payload additionally commits to ``signature_algorithm``
    (a registered scheme id, see ``modelguard.signing.schemes``) and
    ``key_id`` (the fingerprint of the signing public key). Because both
    are inside the signed bytes, an attacker cannot relabel the
    algorithm or present the signature under a different key without
    invalidating it. The unsigned ``signature_type`` must equal the
    signed ``signature_algorithm``.

The optional fields are omitted from the canonical JSON when unset
(``exclude_none``), so a version-1 payload serializes to exactly the
bytes it always did and old signatures keep verifying.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, ValidationError

from modelguard.exceptions import MalformedSignatureError

SIGNATURE_SCHEMA_VERSION = "1"
SCHEMA_VERSION_LEGACY = "1"
SCHEMA_VERSION_BOUND = "2"
SUPPORTED_SCHEMA_VERSIONS = (SCHEMA_VERSION_LEGACY, SCHEMA_VERSION_BOUND)
SIGNATURE_TYPE_ED25519_LOCAL = "ed25519-local"

# A real envelope is about 1 KiB. The cap exists so a hostile file cannot
# make a verifier read gigabytes before any check runs.
MAX_ENVELOPE_BYTES = 64 * 1024


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
    # Format version "2" only; both must be None in version "1".
    signature_algorithm: str | None = None  # registered scheme id
    key_id: str | None = None  # lowercase-hex SHA-256 of the public key bytes

    def canonical_json(self) -> bytes:
        data = self.model_dump(mode="json", exclude_none=True)
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


class SignatureEnvelope(BaseModel):
    """A ``SignaturePayload`` plus its detached signature.

    This is what gets written to a ``.modelguard.sig.json`` file next
    to a signed artifact/manifest/ML-BOM.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    # UNSIGNED. Version-1 payloads: must be "ed25519-local" (the default, kept
    # for old files). Version-2 payloads: must equal payload.signature_algorithm.
    # Never trusted on its own; see modelguard.signing.verifier.
    signature_type: str = SIGNATURE_TYPE_ED25519_LOCAL
    payload: SignaturePayload
    signature: str  # lowercase hex; encoding is defined by the scheme
    public_key: str  # lowercase hex; encoding is defined by the scheme. UNTRUSTED.

    def to_json(self, *, indent: int | None = 2) -> str:
        return self.model_dump_json(indent=indent)


def load_envelope(path: Path) -> SignatureEnvelope:
    """Read and parse a signature file, refusing hostile input cleanly.

    Raises ``MalformedSignatureError`` (never a raw parser error) for a
    file that is too large, not UTF-8, not JSON, nested too deeply, or
    not exactly the envelope schema (unknown fields are rejected).
    Parsing does not verify anything.
    """
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_ENVELOPE_BYTES + 1)
    except OSError as exc:
        raise MalformedSignatureError(f"Cannot read signature file {path}: {exc.strerror}") from exc
    if len(raw) > MAX_ENVELOPE_BYTES:
        raise MalformedSignatureError(
            f"Signature file {path} is larger than {MAX_ENVELOPE_BYTES} bytes; refusing to parse it."
        )
    try:
        return SignatureEnvelope.model_validate(json.loads(raw.decode("utf-8")))
    except ValidationError as exc:
        # Report which fields are wrong, never the offending values (attacker-controlled).
        problems = "; ".join(
            f"{_safe_loc(err['loc'])}: {err['msg']}" for err in exc.errors(include_input=False)[:5]
        )
        raise MalformedSignatureError(
            f"Signature file {path} does not match the signature envelope schema ({problems})."
        ) from exc
    except (ValueError, RecursionError) as exc:
        # UnicodeDecodeError, JSONDecodeError, or nesting too deep for the parser.
        raise MalformedSignatureError(
            f"Signature file {path} is not a valid ModelGuard signature envelope "
            f"({type(exc).__name__})."
        ) from exc


def _safe_loc(loc: tuple[int | str, ...]) -> str:
    """Render a validation error location without echoing raw control characters."""
    text = ".".join(str(part) for part in loc) or "<root>"
    return ascii(text[:60])[1:-1]
