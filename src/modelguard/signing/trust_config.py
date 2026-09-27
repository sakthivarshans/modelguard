"""Structured trust configuration: expiry, per-key revocation, scoping.

Phase 5 trust roots were a flat set of fingerprints: a key was either
trusted or it was not, forever, for every model. This module adds a
small, strict-schema configuration format for a set of trusted keys,
each with its own validity window, status, optional binding to a
claimed signer identity, and optional scoping to specific model_id
patterns.

``--trusted-fingerprint`` / ``ModelGuard(trusted_key_fingerprints=...)``
remain fully supported: :func:`build_minimal_trust_config` turns a flat
set of fingerprints into an equivalent ``TrustConfig`` where each key is
unconstrained (always active, no expiry, no identity or scope binding),
so both paths are evaluated by the same code.

Design trap this module exists to address (see the architecture notes
for Phase 7): the ``signed_at`` timestamp inside a signature payload is
chosen by whoever holds the signing key, so it is attacker-controlled
input, not evidence. **Expiry and revocation are therefore evaluated
against the verifier's own clock (``now``) at the moment of
verification, never against the payload's claimed signing time.**
A consequence that is easy to miss: this means a key's revocation is
effective immediately for every future verification, regardless of
what signing time a signature claims -- an attacker who stole a key
before it was revoked cannot backdate a forged signature to before the
revocation and have it accepted. It also means a signature genuinely
made while a key was active, but presented for verification after the
key's ``not_after``, is correctly refused: this module gives no way to
say "prove this was signed before expiry" -- that is what a trusted
timestamp or transparency log would provide, and ModelGuard does not
have one yet (see the Sigstore discussion in the Phase 7 plan).

What this module does not decide: whether the crypto verifies at all
(``modelguard.signing.verifier``), or what happens to the resulting
decision (that is the caller -- ``ModelGuard.verify()`` or a future
policy rule).
"""

from __future__ import annotations

import fnmatch
import os
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from modelguard.exceptions import TrustConfigurationError
from modelguard.signing.trust import normalize_fingerprints

TRUST_CONFIG_SCHEMA_VERSION = "1"

# A real file with a few dozen keys is a few KiB; this is a generous
# ceiling to stop a hostile or accidentally-huge file from being parsed.
MAX_TRUST_CONFIG_BYTES = 256 * 1024

_FINGERPRINT_RE = re.compile(r"[0-9a-f]{64}")
_ALGORITHM_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
_MAX_STRING_FIELD = 200
_MAX_SCOPE_PATTERNS = 32


class TrustedKeyStatus(str, Enum):
    """A trusted key's current standing, evaluated at verification time."""

    ACTIVE = "active"
    RETIRED = "retired"
    REVOKED = "revoked"


class TrustedKeyEntry(BaseModel):
    """One trusted signing key and the conditions under which it is trusted.

    ``key_id`` is the same SHA-256 fingerprint ``verify_envelope_signature``
    returns -- computed from the key bytes that actually verified a
    signature, never read from an unverified claim.

    ``algorithm`` is optional and, when set, must equal the algorithm
    that verified the signature. Leaving it unset accepts the key
    regardless of scheme (this is what a bare ``--trusted-fingerprint``
    produces, for backward compatibility); setting it pins the entry to
    one scheme, which is recommended whenever the algorithm is known,
    since two schemes could in principle produce colliding-looking
    fingerprints only if they used identically-sized keys with a hash
    collision -- vanishingly unlikely, but pinning costs nothing.

    ``not_before``/``not_after`` must carry an explicit UTC offset (a
    naive datetime is rejected rather than silently assumed to be UTC
    or local time).

    ``signer_identity``, if set, must equal the *claimed*
    ``signer_identity`` in the signed payload. This still does not
    verify the identity string itself (nothing does -- only the key is
    cryptographically checked); it lets a trust entry say "this key
    should only ever be used under this claimed identity", which turns
    an unexpected identity into a trust failure instead of silent
    acceptance.

    ``scope_model_id_patterns``, if set, restricts the key to signing
    models whose ``model_id`` matches at least one pattern
    (``fnmatch``-style, case-sensitive). Empty (the default) means
    unscoped.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    key_id: str
    algorithm: str | None = None
    status: TrustedKeyStatus = TrustedKeyStatus.ACTIVE
    not_before: datetime | None = None
    not_after: datetime | None = None
    signer_identity: str | None = None
    scope_model_id_patterns: tuple[str, ...] = Field(default_factory=tuple)
    label: str | None = None

    @field_validator("key_id", mode="before")
    @classmethod
    def _normalize_key_id(cls, value: Any) -> Any:
        if isinstance(value, str):
            return value.strip().lower().removeprefix("sha256:")
        return value

    @field_validator("key_id")
    @classmethod
    def _validate_key_id(cls, value: str) -> str:
        if not _FINGERPRINT_RE.fullmatch(value):
            raise ValueError(
                "key_id must be 64 lowercase hex characters (the SHA-256 fingerprint of the "
                "raw public key), optionally prefixed with 'sha256:'. Compute one with "
                "`modelguard fingerprint <public-key-file>`."
            )
        return value

    @field_validator("algorithm")
    @classmethod
    def _validate_algorithm(cls, value: str | None) -> str | None:
        if value is not None and not _ALGORITHM_RE.fullmatch(value):
            raise ValueError(
                f"algorithm {value!r} is not a valid scheme identifier "
                "(lowercase letters, digits, and hyphens, 1-64 characters)."
            )
        return value

    @field_validator("not_before", "not_after")
    @classmethod
    def _require_timezone(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError(
                "must include an explicit UTC offset, e.g. '2027-01-01T00:00:00Z' -- a "
                "timestamp with no timezone is ambiguous and is refused rather than guessed."
            )
        return value

    @field_validator("signer_identity", "label")
    @classmethod
    def _bounded_single_line_string(cls, value: str | None) -> str | None:
        return _check_bounded_string(value, field="signer_identity/label")

    @field_validator("scope_model_id_patterns")
    @classmethod
    def _validate_scope_patterns(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) > _MAX_SCOPE_PATTERNS:
            raise ValueError(f"at most {_MAX_SCOPE_PATTERNS} scope_model_id_patterns are allowed.")
        for pattern in value:
            _check_bounded_string(pattern, field="scope_model_id_patterns", allow_none=False)
        return value

    @model_validator(mode="after")
    def _validate_window(self) -> TrustedKeyEntry:
        if self.not_before is not None and self.not_after is not None and self.not_before > self.not_after:
            raise ValueError(
                f"not_before ({self.not_before.isoformat()}) must not be after "
                f"not_after ({self.not_after.isoformat()})."
            )
        return self


def _check_bounded_string(value: str | None, *, field: str, allow_none: bool = True) -> str | None:
    if value is None:
        if allow_none:
            return None
        raise ValueError(f"{field} entries must not be empty.")
    if not value or len(value) > _MAX_STRING_FIELD:
        raise ValueError(f"{field} must be 1-{_MAX_STRING_FIELD} characters.")
    if any(ord(char) < 0x20 for char in value):
        raise ValueError(f"{field} must not contain control characters.")
    return value


class TrustConfig(BaseModel):
    """A validated set of trusted keys, each appearing at most once.

    Rotation with an overlap period is expressed as two *different*
    keys (old fingerprint retired-or-still-active, new fingerprint
    active), not as two entries for the same fingerprint -- allowing
    the latter would make it ambiguous which entry's constraints apply
    to a given verification.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    version: str = TRUST_CONFIG_SCHEMA_VERSION
    keys: tuple[TrustedKeyEntry, ...] = Field(default_factory=tuple)

    @model_validator(mode="after")
    def _validate_unique_key_ids(self) -> TrustConfig:
        seen: set[str] = set()
        for key in self.keys:
            if key.key_id in seen:
                raise ValueError(
                    f"Duplicate trust configuration entry for fingerprint {key.key_id}. Each "
                    "key may appear at most once; express a rotation overlap with two "
                    "different keys, not two entries for the same key."
                )
            seen.add(key.key_id)
        return self


def load_trust_config_file(path: Path) -> TrustConfig:
    """Load and validate a trust configuration YAML/JSON file.

    Uses ``yaml.safe_load`` only (JSON is valid YAML, so this also
    reads ``.json`` files). Raises ``TrustConfigurationError`` for
    anything malformed: oversized file, invalid UTF-8, invalid YAML,
    a non-mapping document, or a document that fails schema validation
    (unknown fields, invalid fingerprints, naive timestamps, and so
    on) -- never a raw ``yaml.YAMLError`` or ``pydantic.ValidationError``.
    """
    try:
        raw_bytes = path.read_bytes()
    except OSError as exc:
        raise TrustConfigurationError(
            f"Cannot read trust configuration file {path}: {exc.strerror}"
        ) from exc
    if len(raw_bytes) > MAX_TRUST_CONFIG_BYTES:
        raise TrustConfigurationError(
            f"Trust configuration file {path} is larger than {MAX_TRUST_CONFIG_BYTES} bytes; "
            "refusing to parse it."
        )
    try:
        raw = yaml.safe_load(raw_bytes.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise TrustConfigurationError(f"Trust configuration file {path} is not valid UTF-8: {exc}") from exc
    except yaml.YAMLError as exc:
        raise TrustConfigurationError(f"Trust configuration file {path} is not valid YAML: {exc}") from exc

    if not isinstance(raw, dict):
        raise TrustConfigurationError(
            f"Trust configuration file {path} must be a YAML mapping with a 'keys' list."
        )
    try:
        return TrustConfig.model_validate(raw)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in err['loc']) or '<root>'}: {err['msg']}"
            for err in exc.errors(include_input=False)[:8]
        )
        raise TrustConfigurationError(
            f"Trust configuration file {path} failed schema validation ({problems})."
        ) from exc


def save_trust_config_file(config: TrustConfig, path: Path) -> None:
    """Write ``config`` to ``path`` as YAML, atomically.

    Writes to a temporary file in the same directory and renames it
    into place, so a crash or concurrent read never observes a
    partially-written file. Does not re-read or re-validate what it
    wrote; callers that mutate a loaded config (add/retire/revoke a
    key) should validate the *in-memory* ``TrustConfig`` -- which
    already happened when it was constructed -- before calling this.
    """
    document = config.model_dump(mode="json", exclude_none=True)
    text = yaml.safe_dump(document, sort_keys=False, default_flow_style=False)
    tmp_path = path.with_name(f"{path.name}.tmp-{os.getpid()}")
    try:
        tmp_path.write_text(text)
        tmp_path.replace(path)
    finally:
        tmp_path.unlink(missing_ok=True)


def build_minimal_trust_config(fingerprints: Iterable[str]) -> TrustConfig:
    """The ``TrustConfig`` equivalent to a flat ``--trusted-fingerprint`` set.

    Every fingerprint becomes an unconstrained, always-active entry:
    any algorithm, no expiry, no identity or scope binding -- exactly
    the Phase 5 behavior. Raises ``TrustConfigurationError`` on an
    empty or invalid collection (via
    ``modelguard.signing.trust.normalize_fingerprints``).
    """
    normalized = normalize_fingerprints(fingerprints)
    return TrustConfig(keys=tuple(TrustedKeyEntry(key_id=fp) for fp in sorted(normalized)))


def merge_trust_configs(*configs: TrustConfig) -> TrustConfig:
    """Combine trust configs from multiple sources (e.g. a file plus
    ad hoc ``--trusted-fingerprint`` flags).

    A fingerprint appearing in more than one source is accepted only
    if every occurrence has *identical* settings; a real conflict
    (the same key configured two different ways) raises
    ``TrustConfigurationError`` rather than silently picking one, since
    the caller could not have known which one would win.
    """
    merged: dict[str, TrustedKeyEntry] = {}
    for config in configs:
        for key in config.keys:
            existing = merged.get(key.key_id)
            if existing is not None and existing != key:
                raise TrustConfigurationError(
                    f"Fingerprint {key.key_id} is configured more than once with different "
                    "settings (for example, once via --trusted-fingerprint and once in a "
                    "trust configuration file). Configure each key in exactly one place."
                )
            merged[key.key_id] = key
    return TrustConfig(keys=tuple(merged.values()))


@dataclass(frozen=True, slots=True)
class TrustEvaluation:
    """The outcome of checking a verified signature against a ``TrustConfig``."""

    trusted: bool
    matched_key: TrustedKeyEntry | None
    reasons: tuple[str, ...]


def evaluate_trust(
    key_fingerprint: str,
    algorithm: str,
    trust_config: TrustConfig,
    *,
    claimed_signer_identity: str | None = None,
    model_id: str | None = None,
    now: datetime | None = None,
) -> TrustEvaluation:
    """Decide whether a key that verified a signature is trusted right now.

    ``key_fingerprint`` and ``algorithm`` must come from a
    ``SignatureCheck`` returned by ``verify_envelope_signature`` --
    i.e. from what actually verified, never from an unverified claim.

    ``now`` defaults to the current UTC time and exists so tests (and
    only tests) can pin the clock; production callers should not pass
    it. See the module docstring for why ``now`` -- not the payload's
    claimed ``signed_at`` -- is what expiry and revocation are checked
    against.
    """
    clock = now if now is not None else datetime.now(UTC)
    matches = [key for key in trust_config.keys if key.key_id == key_fingerprint]
    if not matches:
        return TrustEvaluation(
            False, None, (f"No trusted key is configured with fingerprint {key_fingerprint}.",)
        )
    key = matches[0]  # TrustConfig enforces at most one entry per fingerprint.

    reasons: list[str] = []
    if key.algorithm is not None and key.algorithm != algorithm:
        reasons.append(
            f"Trusted key {key.key_id} is configured for algorithm {key.algorithm!r}, but the "
            f"signature verified as {algorithm!r}."
        )
    if key.status is not TrustedKeyStatus.ACTIVE:
        reasons.append(f"Trusted key {key.key_id} is {key.status.value}, not active.")
    if key.not_before is not None and clock < key.not_before:
        reasons.append(
            f"Trusted key {key.key_id} is not valid until {key.not_before.isoformat()} "
            f"(current time {clock.isoformat()})."
        )
    if key.not_after is not None and clock > key.not_after:
        reasons.append(
            f"Trusted key {key.key_id} expired at {key.not_after.isoformat()} "
            f"(current time {clock.isoformat()})."
        )
    if key.signer_identity is not None and key.signer_identity != claimed_signer_identity:
        reasons.append(
            f"Trusted key {key.key_id} is bound to signer identity {key.signer_identity!r}, "
            f"but the signature claims signer identity {claimed_signer_identity!r}."
        )
    if key.scope_model_id_patterns:
        scoped_match = model_id is not None and any(
            fnmatch.fnmatchcase(model_id, pattern) for pattern in key.scope_model_id_patterns
        )
        if not scoped_match:
            reasons.append(
                f"Trusted key {key.key_id} is scoped to model_id pattern(s) "
                f"{list(key.scope_model_id_patterns)}, which does not match "
                f"model_id {model_id!r}."
            )

    return TrustEvaluation(not reasons, key, tuple(reasons))
