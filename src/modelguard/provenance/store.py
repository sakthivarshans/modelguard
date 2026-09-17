"""Local, file-backed provenance store.

Events are appended to a hash-chained JSONL log (see
``modelguard.audit.chain``) so the lineage history itself is
tamper-evident, not just the artifacts it describes.
"""

from __future__ import annotations

from pathlib import Path

from modelguard.audit.chain import append_entry, read_all_entries, verify_chain
from modelguard.provenance.models import ProvenanceEvent


class LocalProvenanceStore:
    """A provenance store backed by a single hash-chained JSONL file.

    This is the ``ProvenanceStore`` adapter used when no external
    database is configured. A future PostgreSQL-backed adapter
    implementing the same methods can replace it without changing
    callers, per the project's adapter-boundary rule.
    """

    def __init__(self, path: Path) -> None:
        self.path = path

    def record(self, event: ProvenanceEvent) -> ProvenanceEvent:
        append_entry(self.path, event.to_record())
        return event

    def all_events(self) -> list[ProvenanceEvent]:
        return [ProvenanceEvent.from_record(e.record) for e in read_all_entries(self.path)]

    def verify(self) -> None:
        """Raise ``ChainIntegrityError`` if the log has been tampered with."""
        verify_chain(self.path)
