from __future__ import annotations

from pathlib import Path

from modelguard.provenance.graph import (
    children,
    find_deployments_using_revoked_model,
    find_models_derived_from,
    lineage,
    parents,
)
from modelguard.provenance.models import ProvenanceEvent
from modelguard.provenance.store import LocalProvenanceStore


def _store(tmp_path: Path) -> LocalProvenanceStore:
    return LocalProvenanceStore(tmp_path / "events.jsonl")


def test_record_and_read_events(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.record(
        ProvenanceEvent(
            subject_id="fine-tuned-a",
            relationship="FINE_TUNED_FROM",
            object_id="base-model",
            actor="dev@example.com",
        )
    )

    events = store.all_events()
    assert len(events) == 1
    assert events[0].subject_id == "fine-tuned-a"


def test_parents_and_children(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.record(
        ProvenanceEvent(
            subject_id="fine-tuned-a", relationship="FINE_TUNED_FROM", object_id="base",
            actor="dev@example.com",
        )
    )

    assert [e.object_id for e in parents(store, "fine-tuned-a")] == ["base"]
    assert [e.subject_id for e in children(store, "base")] == ["fine-tuned-a"]
    assert parents(store, "base") == []


def test_lineage_walks_multiple_generations(tmp_path: Path) -> None:
    store = _store(tmp_path)
    # base -> fine-tuned -> quantized
    store.record(
        ProvenanceEvent(
            subject_id="fine-tuned", relationship="FINE_TUNED_FROM", object_id="base",
            actor="dev@example.com",
        )
    )
    store.record(
        ProvenanceEvent(
            subject_id="quantized", relationship="QUANTIZED_FROM", object_id="fine-tuned",
            actor="dev@example.com",
        )
    )

    ancestors = {e.object_id for e in lineage(store, "quantized")}
    assert ancestors == {"fine-tuned", "base"}


def test_lineage_handles_cycles_defensively(tmp_path: Path) -> None:
    """Lineage should be a DAG, but a corrupted/malicious event set
    could claim a -> b -> a. The traversal must terminate rather than
    loop forever.
    """
    store = _store(tmp_path)
    store.record(
        ProvenanceEvent(
            subject_id="a", relationship="DERIVED_FROM", object_id="b", actor="attacker",
        )
    )
    store.record(
        ProvenanceEvent(
            subject_id="b", relationship="DERIVED_FROM", object_id="a", actor="attacker",
        )
    )

    result = lineage(store, "a")  # must terminate
    assert len(result) >= 1


def test_find_models_derived_from(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.record(
        ProvenanceEvent(
            subject_id="fine-tuned", relationship="FINE_TUNED_FROM", object_id="base",
            actor="dev@example.com",
        )
    )
    store.record(
        ProvenanceEvent(
            subject_id="quantized", relationship="QUANTIZED_FROM", object_id="fine-tuned",
            actor="dev@example.com",
        )
    )
    store.record(
        ProvenanceEvent(
            subject_id="unrelated", relationship="DERIVED_FROM", object_id="other-base",
            actor="dev@example.com",
        )
    )

    derived = find_models_derived_from(store, "base")
    assert derived == ["fine-tuned", "quantized"]


def test_non_lineage_relationships_are_excluded_from_graph_traversal(tmp_path: Path) -> None:
    """SIGNED_BY, DEPLOYED_TO etc. point at non-model entities and must
    not be treated as lineage edges.
    """
    store = _store(tmp_path)
    store.record(
        ProvenanceEvent(
            subject_id="demo-model", relationship="SIGNED_BY", object_id="dev@example.com",
            actor="dev@example.com",
        )
    )

    assert parents(store, "demo-model") == []
    assert find_models_derived_from(store, "dev@example.com") == []


def test_find_deployments_using_revoked_model_direct_and_transitive(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.record(
        ProvenanceEvent(
            subject_id="fine-tuned", relationship="FINE_TUNED_FROM", object_id="base",
            actor="dev@example.com",
        )
    )
    store.record(
        ProvenanceEvent(
            subject_id="base", relationship="DEPLOYED_TO", object_id="prod-cluster-1",
            actor="ops@example.com",
        )
    )
    store.record(
        ProvenanceEvent(
            subject_id="fine-tuned", relationship="DEPLOYED_TO", object_id="prod-cluster-2",
            actor="ops@example.com",
        )
    )
    store.record(
        ProvenanceEvent(
            subject_id="unrelated-model", relationship="DEPLOYED_TO", object_id="prod-cluster-3",
            actor="ops@example.com",
        )
    )

    affected = find_deployments_using_revoked_model(store, {"base"})
    deployment_targets = {e.object_id for e in affected}

    # Both the directly-revoked model's deployment and the deployment
    # of a model fine-tuned from it must be flagged.
    assert deployment_targets == {"prod-cluster-1", "prod-cluster-2"}
