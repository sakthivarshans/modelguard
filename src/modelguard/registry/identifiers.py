"""Shared validation for registry identifiers (``model_id`` / ``version``).

Every ``Registry`` backend must accept and reject the same identifiers,
otherwise a model registered in one backend could not be exported to
another, and "what is a valid name" would depend on where you happen to
store it. The rules are deliberately conservative:

* non-empty, at most ``MAX_IDENTIFIER_LENGTH`` characters;
* not ``.`` or ``..``, and no ``/`` or ``\\`` (path traversal for
  file-backed registries; also keeps names unambiguous in URIs);
* no control characters (including NUL, which PostgreSQL text cannot
  store) and no leading/trailing whitespace ("demo" vs "demo " is a
  look-alike attack, not a feature);
* Unicode NFC-normalized, so the composed and decomposed spellings of
  the same visible name cannot be registered as two different models.

Not covered: visually confusable characters from different scripts
(e.g. Cyrillic "а" vs Latin "a"). That needs a policy decision about
allowed scripts and is listed in ``docs/limitations.md``.
"""

from __future__ import annotations

import unicodedata

from modelguard.exceptions import ModelGuardError

MAX_IDENTIFIER_LENGTH = 200


class InvalidIdentifierError(ModelGuardError):
    """A model_id or version failed registry identifier validation."""


def validate_identifier(value: str, *, field: str = "identifier") -> str:
    """Return ``value`` unchanged if valid, else raise ``InvalidIdentifierError``."""
    problem = _problem(value)
    if problem is not None:
        raise InvalidIdentifierError(f"Unsafe registry {field} {value[:60]!r}: {problem}.")
    return value


def _problem(value: str) -> str | None:
    if not value:
        return "must not be empty"
    if len(value) > MAX_IDENTIFIER_LENGTH:
        return f"longer than {MAX_IDENTIFIER_LENGTH} characters"
    if value in {".", ".."}:
        return "must not be '.' or '..'"
    if "/" in value or "\\" in value:
        return "must not contain path separators"
    if any(unicodedata.category(ch) == "Cc" for ch in value):
        return "must not contain control characters"
    if value != value.strip():
        return "must not have leading or trailing whitespace"
    if unicodedata.normalize("NFC", value) != value:
        return "must be Unicode NFC-normalized"
    return None
