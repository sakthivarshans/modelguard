"""Generic deployment admission hook.

``admit()`` is what a deployment system (a CI deploy job, a container
entrypoint, a Kubernetes admission webhook you write yourself) calls
before letting a model run. It is deliberately small: it is NOT a
Kubernetes webhook, a server, or an enforcement mechanism by itself --
it returns a decision, and the caller is responsible for actually
refusing to deploy on ``admitted=False``.

Fail-closed rules, each tested:

* No trusted key fingerprints configured -> not admitted. Admission
  without a trust root would admit anything signed by anyone.
* Any exception while checking (malformed files, unsafe paths, bad
  policy) -> not admitted, with the error surfaced in ``reasons``.
  A gate that lets an artifact through because the check crashed is
  worse than no gate.
* An audit log was requested but the record could not be written ->
  not admitted. A decision that cannot be recorded is not accepted.
* ``admitted`` requires ALL of: an ALLOW/ALLOW_WITH_WARNINGS policy
  decision, the artifact digest matching the signature, and the signer
  being in the trusted set -- independent of what the policy file
  enables, so a weak policy cannot admit an untrusted or tampered
  artifact.

What it cannot do: it checks the artifact at the moment of the call.
Anything that can modify the files between this check and the moment
the model is loaded (a writable volume, a swapped mount) defeats it;
see "check-to-use window" in ``docs/security/threat-model.md``.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, replace
from pathlib import Path

from modelguard.audit.log import AuditEvent, LocalAuditLog
from modelguard.exceptions import AdmissionDenied
from modelguard.policy.models import Decision
from modelguard.sdk import ModelGuard


@dataclass(frozen=True, slots=True)
class AdmissionDecision:
    """The outcome of an admission check, with the evidence behind it."""

    admitted: bool
    reasons: tuple[str, ...]
    correlation_id: str
    decision: Decision | None = None
    subject: str | None = None
    artifact_digest: str | None = None
    evaluation_id: str | None = None
    # Honest coverage flags: what the check actually did.
    revocation_checked: bool = False
    digest_from_cache: bool = False
    audited: bool = False
    error: str | None = None

    def raise_if_blocked(self) -> None:
        if not self.admitted:
            raise AdmissionDenied(list(self.reasons))


def admit(
    guard: ModelGuard,
    artifact_path: str | Path,
    mbom_path: str | Path,
    signature_path: str | Path,
    policy_path: str | Path,
    *,
    actor: str,
    audit_log_path: str | Path | None = None,
) -> AdmissionDecision:
    """Decide whether ``artifact_path`` may be deployed.

    ``guard`` must have been constructed with ``trusted_key_fingerprints``.
    ``actor`` identifies who or what is requesting deployment and is
    written to the audit record (do not pass secrets). If
    ``audit_log_path`` is given, the decision is appended to a
    hash-chained audit log; the log is single-writer (see
    ``docs/limitations.md``).

    Never raises for an expected failure; returns ``admitted=False``.
    """
    correlation_id = str(uuid.uuid4())

    if guard.trusted_key_fingerprints is None:
        return _finish(
            AdmissionDecision(
                admitted=False,
                reasons=(
                    (
                        "No trusted signer keys are configured. Admission requires an "
                        "explicit trust root: construct "
                        "ModelGuard(trusted_key_fingerprints=[...])."
                    ),
                ),
                correlation_id=correlation_id,
            ),
            actor,
            audit_log_path,
        )

    try:
        check = guard.check_policy_detailed(artifact_path, mbom_path, signature_path, policy_path)
    except Exception as exc:  # noqa: BLE001 -- a gate must fail closed on ANY error
        return _finish(
            AdmissionDecision(
                admitted=False,
                reasons=(f"Admission check failed with {type(exc).__name__}: {exc}",),
                correlation_id=correlation_id,
                error=type(exc).__name__,
            ),
            actor,
            audit_log_path,
        )

    verification = check.verification
    result = check.decision

    reasons: list[str] = []
    if not result.decision.is_allowed:
        reasons.append(f"Policy decision was {result.decision.value}.")
        reasons.extend(f"{r.rule}: {r.message}" for r in result.failed_rules)
    if not verification.digest_matches:
        reasons.append("The artifact does not match the digest bound in its signature.")
    if verification.signer_trusted is not True:
        reasons.append("The artifact was not signed by a trusted key.")

    return _finish(
        AdmissionDecision(
            admitted=not reasons,
            reasons=tuple(reasons),
            correlation_id=correlation_id,
            decision=result.decision,
            subject=result.subject,
            artifact_digest=verification.artifact_digest if verification.digest_matches else None,
            evaluation_id=result.evaluation_id,
            revocation_checked=verification.revocation_checked,
            digest_from_cache=verification.digest_from_cache,
        ),
        actor,
        audit_log_path,
    )


def _finish(
    decision: AdmissionDecision, actor: str, audit_log_path: str | Path | None
) -> AdmissionDecision:
    """Record the decision (if auditing was requested), failing closed
    if the record cannot be written."""
    if audit_log_path is None:
        return decision

    summary = "; ".join(decision.reasons)[:500] if decision.reasons else "admitted"
    event = AuditEvent(
        event_type="deployment.admission",
        actor=actor,
        subject=decision.subject or "unknown",
        artifact_digest=decision.artifact_digest,
        result="success" if decision.admitted else "failure",
        reason=summary,
        correlation_id=decision.correlation_id,
    )
    try:
        LocalAuditLog(Path(audit_log_path)).record(event)
    except Exception as exc:  # noqa: BLE001 -- an unrecordable decision is not accepted
        unauditable = (
            "The admission decision could not be written to the audit log "
            f"({type(exc).__name__}); refusing to admit an unauditable deployment."
        )
        return replace(
            decision,
            admitted=False,
            reasons=(*decision.reasons, unauditable),
            audited=False,
            error=type(exc).__name__,
        )
    return replace(decision, audited=True)
