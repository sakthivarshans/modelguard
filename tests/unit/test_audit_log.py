from __future__ import annotations

from pathlib import Path

import pytest

from modelguard.audit.chain import ChainIntegrityError
from modelguard.audit.log import AuditEvent, LocalAuditLog


def test_record_and_read_events(tmp_path: Path) -> None:
    log = LocalAuditLog(tmp_path / "audit.jsonl")
    log.record(
        AuditEvent(
            event_type="model.registered",
            actor="dev@example.com",
            subject="demo@1.0.0",
            artifact_digest="sha256:abc",
            result="success",
        )
    )
    log.record(
        AuditEvent(
            event_type="model.revoked",
            actor="security@example.com",
            subject="demo@1.0.0",
            artifact_digest="sha256:abc",
            result="success",
            reason="compromised training data",
        )
    )

    events = log.all_events()
    assert len(events) == 2
    assert events[0].event_type == "model.registered"
    assert events[1].reason == "compromised training data"


def test_audit_log_verify_detects_tampering(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = LocalAuditLog(path)
    log.record(
        AuditEvent(
            event_type="model.registered",
            actor="dev@example.com",
            subject="demo@1.0.0",
            artifact_digest="sha256:abc",
            result="success",
        )
    )

    log.verify()  # untampered: must not raise

    # Simulate an attacker editing the audit log directly on disk.
    text = path.read_text().replace("model.registered", "model.revoked")
    path.write_text(text)

    with pytest.raises(ChainIntegrityError):
        log.verify()


def test_audit_events_never_contain_a_secret_field() -> None:
    """Structural guard: AuditEvent has no field named for credentials,
    so callers cannot accidentally serialize one through this type.
    """
    field_names = set(AuditEvent.__dataclass_fields__.keys())
    forbidden = {"secret", "password", "token", "private_key", "credential"}
    assert not (field_names & forbidden)
