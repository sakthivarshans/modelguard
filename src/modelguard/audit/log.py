"""Audit logging.

Every registry and provenance operation that matters for a security
review is recorded here: who/what performed it, which artifact was
involved, and when. Records are appended to a hash-chained log (see
``modelguard.audit.chain``) so that edits or deletions in the middle
of the log are detectable.

Consistent with the project's rules: never log secrets. This module's
event schema has no field for key material, tokens, or credentials,
and callers must not put them in ``details``.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from modelguard.audit.chain import ChainEntry, append_entry, read_all_entries, verify_chain

AuditEventType = Literal[
    "model.registered",
    "model.revoked",
    "model.unrevoked",
    "provenance.event_recorded",
]


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """One audit record."""

    event_type: AuditEventType
    actor: str
    subject: str  # typically a model_id or model_id@version
    artifact_digest: str | None
    result: Literal["success", "failure"]
    reason: str | None = None
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_record(self) -> dict[str, Any]:
        return {
            "event_type": self.event_type,
            "actor": self.actor,
            "subject": self.subject,
            "artifact_digest": self.artifact_digest,
            "result": self.result,
            "reason": self.reason,
            "correlation_id": self.correlation_id,
            "timestamp": self.timestamp,
        }


class LocalAuditLog:
    """A hash-chained audit log backed by a single JSONL file."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def record(self, event: AuditEvent) -> ChainEntry:
        return append_entry(self.path, event.to_record())

    def all_events(self) -> list[AuditEvent]:
        return [_entry_to_event(e) for e in read_all_entries(self.path)]

    def verify(self) -> None:
        """Raise ``ChainIntegrityError`` if the log has been tampered with."""
        verify_chain(self.path)


def _entry_to_event(entry: ChainEntry) -> AuditEvent:
    r = entry.record
    return AuditEvent(
        event_type=r["event_type"],
        actor=r["actor"],
        subject=r["subject"],
        artifact_digest=r.get("artifact_digest"),
        result=r["result"],
        reason=r.get("reason"),
        correlation_id=r["correlation_id"],
        timestamp=r["timestamp"],
    )
