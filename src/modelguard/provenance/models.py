"""Provenance data model.

A ``ProvenanceEvent`` records one edge in the model lineage graph:
some subject artifact stands in a named relationship to some object
artifact (or a non-artifact entity, for ``DEPLOYED_TO`` and
``SIGNED_BY``). Events are immutable and append-only -- correcting a
mistake means recording a new event, never editing an old one.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

RelationshipType = Literal[
    "DERIVED_FROM",
    "TRAINED_ON",
    "FINE_TUNED_FROM",
    "MERGED_FROM",
    "QUANTIZED_FROM",
    "EXPORTED_FROM",
    "PACKAGED_IN",
    "SIGNED_BY",
    "BUILT_BY",
    "EVALUATED_BY",
    "DEPLOYED_TO",
    "REVOKED_BY",
]

# Relationship types whose "object" is a model identifier, and therefore
# participate in lineage graph traversal (parents/children/ancestors).
# The others (SIGNED_BY, DEPLOYED_TO, EVALUATED_BY, BUILT_BY, REVOKED_BY)
# point at a non-model entity (a signer, an environment, an evaluator)
# and are recorded for audit purposes but do not form model-to-model edges.
LINEAGE_RELATIONSHIPS: frozenset[RelationshipType] = frozenset(
    {
        "DERIVED_FROM",
        "TRAINED_ON",
        "FINE_TUNED_FROM",
        "MERGED_FROM",
        "QUANTIZED_FROM",
        "EXPORTED_FROM",
        "PACKAGED_IN",
    }
)


@dataclass(frozen=True, slots=True)
class ProvenanceEvent:
    """One provenance edge: ``subject_id --relationship--> object_id``."""

    subject_id: str
    relationship: RelationshipType
    object_id: str
    actor: str
    evidence: Literal["DECLARED", "SIGNED", "VERIFIED", "HUMAN_APPROVED"] = "DECLARED"
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_record(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "subject_id": self.subject_id,
            "relationship": self.relationship,
            "object_id": self.object_id,
            "actor": self.actor,
            "evidence": self.evidence,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> ProvenanceEvent:
        return cls(
            event_id=record["event_id"],
            subject_id=record["subject_id"],
            relationship=record["relationship"],
            object_id=record["object_id"],
            actor=record["actor"],
            evidence=record["evidence"],
            timestamp=record["timestamp"],
        )
