"""Explicit trust roots for signer verification.

Until Phase 5, ``verify()`` accepted any valid signature from any
public key embedded in the signature file, so an attacker could re-sign
a tampered model with their own key and pass. A trust root is the
caller's explicit statement of *which* public keys they accept.

A trust root here is a **fingerprint**: the lowercase hex SHA-256 of
the raw 32-byte Ed25519 public key. Fingerprints (rather than key
files) are used because they are short enough to live in a CI variable
or a deployment config, and because they are compared against the key
that actually verified the signature -- there is no separate identity
string to confuse.

What this does NOT provide: key rotation workflows, expiry, revocation
of individual keys (remove the fingerprint from the set), or any
binding between the human-readable ``signer_identity`` and the key --
that string remains an unverified claim. See ``docs/limitations.md``.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable

from modelguard.exceptions import TrustConfigurationError

_FINGERPRINT_RE = re.compile(r"[0-9a-f]{64}")


def public_key_fingerprint(public_key_hex: str) -> str:
    """SHA-256 fingerprint (lowercase hex) of a raw hex-encoded public key.

    Raises ``TrustConfigurationError`` if the input is not valid hex.
    """
    try:
        raw = bytes.fromhex(public_key_hex)
    except ValueError as exc:
        raise TrustConfigurationError(f"Public key is not valid hex: {exc}") from exc
    return hashlib.sha256(raw).hexdigest()


def normalize_fingerprints(fingerprints: Iterable[str]) -> frozenset[str]:
    """Validate and normalize a collection of trusted fingerprints.

    Accepts an optional ``sha256:`` prefix and any letter case. Raises
    ``TrustConfigurationError`` on an empty collection or any entry that
    is not exactly 64 hex characters.
    """
    normalized: set[str] = set()
    for raw in fingerprints:
        candidate = raw.strip().lower().removeprefix("sha256:")
        if not _FINGERPRINT_RE.fullmatch(candidate):
            raise TrustConfigurationError(
                f"Invalid trusted key fingerprint {raw!r}: expected 64 hex characters "
                "(the SHA-256 of the raw public key). Compute one with "
                "`modelguard fingerprint <public-key-file>`."
            )
        normalized.add(candidate)
    if not normalized:
        raise TrustConfigurationError(
            "An empty set of trusted key fingerprints was supplied. Pass at least one "
            "fingerprint, or omit trust configuration entirely (in which case no signer "
            "is considered trusted and admission checks will refuse to proceed)."
        )
    return frozenset(normalized)
