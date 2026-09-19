from __future__ import annotations

import json
from pathlib import Path

import pytest

from modelguard.admission import admit
from modelguard.audit.log import LocalAuditLog
from modelguard.exceptions import AdmissionDenied
from modelguard.policy.models import Decision
from modelguard.sdk import ModelGuard
from tests.conftest import PERMISSIVE_POLICY, SignedModel


def _admit(signed: SignedModel, guard: ModelGuard, **kw: object):  # type: ignore[no-untyped-def]
    return admit(
        guard,
        signed.artifact,
        signed.mbom_path,
        signed.sig_path,
        kw.pop("policy_path", signed.policy_path),  # type: ignore[arg-type]
        actor="deploy-bot",
        **kw,  # type: ignore[arg-type]
    )


def test_admits_a_valid_trusted_artifact(signed_model: SignedModel) -> None:
    guard = ModelGuard(trusted_key_fingerprints=[signed_model.fingerprint])
    decision = _admit(signed_model, guard)
    assert decision.admitted
    assert decision.decision == Decision.ALLOW
    assert decision.artifact_digest is not None
    assert decision.subject == "demo@1.0.0"
    decision.raise_if_blocked()  # does not raise


def test_refuses_when_no_trust_roots_are_configured(signed_model: SignedModel) -> None:
    decision = _admit(signed_model, ModelGuard())
    assert not decision.admitted
    assert "trust root" in decision.reasons[0]
    with pytest.raises(AdmissionDenied):
        decision.raise_if_blocked()


def test_refuses_a_tampered_artifact(signed_model: SignedModel) -> None:
    (signed_model.artifact / "weights.bin").write_bytes(b"tampered")
    guard = ModelGuard(trusted_key_fingerprints=[signed_model.fingerprint])
    decision = _admit(signed_model, guard)
    assert not decision.admitted
    assert decision.decision == Decision.DENY
    assert decision.artifact_digest is None  # never reports a digest it could not vouch for


def test_refuses_an_untrusted_signer(signed_model: SignedModel) -> None:
    decision = _admit(signed_model, ModelGuard(trusted_key_fingerprints=["c" * 64]))
    assert not decision.admitted
    assert any("trusted key" in r for r in decision.reasons)


def test_weak_policy_cannot_admit_a_tampered_or_untrusted_artifact(
    signed_model: SignedModel, tmp_path: Path
) -> None:
    """Admission's own gates are independent of what the policy enables."""
    permissive = tmp_path / "permissive.yaml"
    permissive.write_text(PERMISSIVE_POLICY)

    untrusted = _admit(signed_model, ModelGuard(trusted_key_fingerprints=["d" * 64]), policy_path=permissive)
    assert not untrusted.admitted

    (signed_model.artifact / "weights.bin").write_bytes(b"tampered")
    tampered = _admit(
        signed_model,
        ModelGuard(trusted_key_fingerprints=[signed_model.fingerprint]),
        policy_path=permissive,
    )
    assert not tampered.admitted


def test_any_exception_during_the_check_fails_closed(signed_model: SignedModel, tmp_path: Path) -> None:
    guard = ModelGuard(trusted_key_fingerprints=[signed_model.fingerprint])
    bad_policy = tmp_path / "bad.yaml"
    bad_policy.write_text("this: is: not: valid: yaml: [")
    decision = _admit(signed_model, guard, policy_path=bad_policy)
    assert not decision.admitted
    assert decision.error is not None


def test_missing_signature_file_fails_closed(signed_model: SignedModel) -> None:
    guard = ModelGuard(trusted_key_fingerprints=[signed_model.fingerprint])
    signed_model.sig_path.unlink()
    assert not _admit(signed_model, guard).admitted


def test_revocation_coverage_is_reported_honestly(signed_model: SignedModel) -> None:
    guard = ModelGuard(trusted_key_fingerprints=[signed_model.fingerprint])
    assert _admit(signed_model, guard).revocation_checked is False


def test_decisions_are_written_to_a_verifiable_audit_log(signed_model: SignedModel, tmp_path: Path) -> None:
    log_path = tmp_path / "audit" / "admission.jsonl"
    guard = ModelGuard(trusted_key_fingerprints=[signed_model.fingerprint])

    allowed = _admit(signed_model, guard, audit_log_path=log_path)
    (signed_model.artifact / "weights.bin").write_bytes(b"tampered")
    denied = _admit(signed_model, guard, audit_log_path=log_path)

    assert allowed.audited and denied.audited
    log = LocalAuditLog(log_path)
    log.verify()
    events = log.all_events()
    assert [e.result for e in events] == ["success", "failure"]
    assert all(e.event_type == "deployment.admission" and e.actor == "deploy-bot" for e in events)
    assert events[0].correlation_id == allowed.correlation_id


def test_admission_is_refused_if_the_audit_record_cannot_be_written(
    signed_model: SignedModel, tmp_path: Path
) -> None:
    unwritable = tmp_path / "is_a_file"
    unwritable.write_text("x")
    guard = ModelGuard(trusted_key_fingerprints=[signed_model.fingerprint])
    decision = _admit(signed_model, guard, audit_log_path=unwritable / "log.jsonl")
    assert not decision.admitted
    assert not decision.audited
    assert any("audit log" in r for r in decision.reasons)


def test_audit_records_contain_no_key_material(signed_model: SignedModel, tmp_path: Path) -> None:
    log_path = tmp_path / "a.jsonl"
    _admit(signed_model, ModelGuard(trusted_key_fingerprints=[signed_model.fingerprint]), audit_log_path=log_path)
    text = log_path.read_text()
    private_hex = signed_model.keypair.private_key.private_bytes_raw().hex()
    assert private_hex not in text
    assert json.loads(text.splitlines()[0])["record"]["event_type"] == "deployment.admission"
