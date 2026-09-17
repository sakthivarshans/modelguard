"""Lineage graph queries over a ``LocalProvenanceStore``.

Phase 2 implements these as in-memory traversals over the full event
list rather than a graph database, per the architecture document's
explicit guidance: "Do not start with a graph database unless actual
query requirements justify it." For the artifact counts this local
framework targets, loading all events and traversing them in memory is
fast and, importantly, easy to test and reason about.
"""

from __future__ import annotations

from modelguard.provenance.models import LINEAGE_RELATIONSHIPS, ProvenanceEvent
from modelguard.provenance.store import LocalProvenanceStore


def parents(store: LocalProvenanceStore, model_id: str) -> list[ProvenanceEvent]:
    """Direct lineage parents: events where ``model_id`` is the subject
    of a lineage relationship (e.g. "model_id FINE_TUNED_FROM base").
    """
    return [
        e
        for e in store.all_events()
        if e.subject_id == model_id and e.relationship in LINEAGE_RELATIONSHIPS
    ]


def children(store: LocalProvenanceStore, model_id: str) -> list[ProvenanceEvent]:
    """Direct lineage children: events where ``model_id`` is the object
    of a lineage relationship (i.e. something was derived from it).
    """
    return [
        e
        for e in store.all_events()
        if e.object_id == model_id and e.relationship in LINEAGE_RELATIONSHIPS
    ]


def lineage(store: LocalProvenanceStore, model_id: str) -> list[ProvenanceEvent]:
    """Full ancestor chain: walk parents transitively, breadth-first,
    stopping if a cycle is encountered (defensive -- lineage should be
    a DAG, but a corrupted or malicious event set could claim a cycle).
    """
    events = store.all_events()
    visited: set[str] = {model_id}
    frontier = [model_id]
    result: list[ProvenanceEvent] = []

    while frontier:
        current = frontier.pop()
        direct_parents = [
            e for e in events if e.subject_id == current and e.relationship in LINEAGE_RELATIONSHIPS
        ]
        for edge in direct_parents:
            result.append(edge)
            if edge.object_id not in visited:
                visited.add(edge.object_id)
                frontier.append(edge.object_id)

    return result


def find_models_derived_from(store: LocalProvenanceStore, base_model_id: str) -> list[str]:
    """All model IDs transitively derived from ``base_model_id``."""
    events = store.all_events()
    visited: set[str] = set()
    frontier = [base_model_id]

    while frontier:
        current = frontier.pop()
        direct_children = [
            e
            for e in events
            if e.object_id == current and e.relationship in LINEAGE_RELATIONSHIPS
        ]
        for edge in direct_children:
            if edge.subject_id not in visited:
                visited.add(edge.subject_id)
                frontier.append(edge.subject_id)

    return sorted(visited)


def find_deployments_using_revoked_model(
    store: LocalProvenanceStore, revoked_model_ids: set[str]
) -> list[ProvenanceEvent]:
    """DEPLOYED_TO events whose subject is directly revoked, or is
    transitively derived from a revoked model.

    This is a deliberately conservative query: a model built on top of
    revoked provenance is flagged even if the derivative artifact
    itself was never explicitly revoked, since its trustworthiness
    inherits from its ancestor.
    """
    events = store.all_events()
    affected: set[str] = set(revoked_model_ids)
    for revoked_id in revoked_model_ids:
        affected.update(find_models_derived_from(store, revoked_id))

    return [e for e in events if e.relationship == "DEPLOYED_TO" and e.subject_id in affected]
