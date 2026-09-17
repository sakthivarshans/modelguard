"""Deterministic policy evaluation.

``evaluate()`` is a pure function: the same ``PolicyEvaluationContext``
and ``PolicyDocument`` always produce the same ``PolicyDecisionResult``.
It does no I/O, no hashing, no signature checking -- all of that
happens upstream (``ModelGuard.verify()``) and is fed in as booleans on
the context. This keeps the rule logic easy to test exhaustively and
easy to audit, per the architecture document's "Security decisions
must be deterministic" rule.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from modelguard.manifest.models import Manifest
from modelguard.mbom.models import MLBOM
from modelguard.policy.models import (
    ACTION_TO_DECISION,
    Decision,
    PolicyDecisionResult,
    PolicyDocument,
    RuleResult,
)


@dataclass(frozen=True, slots=True)
class PolicyEvaluationContext:
    """Everything a policy rule is allowed to look at.

    Deliberately a flat set of booleans/strings rather than passing
    the full ``Manifest``/``MLBOM``/``VerificationResult`` objects
    through to rule functions: it keeps each rule's dependency on the
    rest of the system explicit and small, and makes the context easy
    to construct directly in tests without a full sign/verify pipeline.
    """

    subject: str
    signature_valid: bool
    mbom_valid: bool
    revoked: bool
    has_license: bool
    has_declared_lineage: bool


def build_context(
    manifest: Manifest,
    mbom: MLBOM,
    *,
    signature_valid: bool,
    mbom_valid: bool,
    revoked: bool,
) -> PolicyEvaluationContext:
    """Build a context from a manifest, ML-BOM, and the boolean results
    already computed by ``ModelGuard.verify()``.
    """
    subject = f"{manifest.model_id or 'unknown'}@{manifest.version or 'unknown'}"
    has_license = bool(manifest.license or mbom.modelguard.license)
    has_lineage = bool(mbom.modelguard.parent_models)
    return PolicyEvaluationContext(
        subject=subject,
        signature_valid=signature_valid,
        mbom_valid=mbom_valid,
        revoked=revoked,
        has_license=has_license,
        has_declared_lineage=has_lineage,
    )


def _check_require_valid_signature(ctx: PolicyEvaluationContext) -> tuple[bool, str]:
    if ctx.signature_valid:
        return True, "A valid signature was found."
    return False, (
        "No valid signature was found. Expected: a signature verifiable against a "
        "known public key. Suggested action: sign the artifact with `modelguard sign` "
        "before registering or deploying it."
    )


def _check_require_ml_bom(ctx: PolicyEvaluationContext) -> tuple[bool, str]:
    if ctx.mbom_valid:
        return True, "A matching ML-BOM was supplied."
    return False, (
        "No valid ML-BOM was supplied, or it does not match the signed digest. "
        "Expected: an ML-BOM generated with `modelguard mbom generate` and bound to "
        "this artifact's signature. Suggested action: regenerate and re-sign."
    )


def _check_require_known_lineage(ctx: PolicyEvaluationContext) -> tuple[bool, str]:
    if ctx.has_declared_lineage:
        return True, "The ML-BOM declares at least one parent model."
    return False, (
        "The ML-BOM does not declare any parent model. Expected: at least one "
        "parent_models entry. Suggested action: regenerate the ML-BOM with "
        "DeclaredProvenance(parent_models=[...])."
    )


def _check_require_license(ctx: PolicyEvaluationContext) -> tuple[bool, str]:
    if ctx.has_license:
        return True, "A license is declared."
    return False, (
        "No license is declared on the manifest or ML-BOM. Expected: a license "
        "identifier. Suggested action: re-run `modelguard manifest --license ...`."
    )


def _check_reject_revoked_models(ctx: PolicyEvaluationContext) -> tuple[bool, str]:
    if not ctx.revoked:
        return True, "The model is not revoked."
    return False, "The model has been revoked."


_RULE_CHECKS: dict[str, Callable[[PolicyEvaluationContext], tuple[bool, str]]] = {
    "require_valid_signature": _check_require_valid_signature,
    "require_ml_bom": _check_require_ml_bom,
    "require_known_lineage": _check_require_known_lineage,
    "require_license": _check_require_license,
    "reject_revoked_models": _check_reject_revoked_models,
}


def evaluate(context: PolicyEvaluationContext, policy: PolicyDocument) -> PolicyDecisionResult:
    """Evaluate every configured rule and return the most severe
    triggered decision.

    A rule with ``enabled: false`` (or simply absent from the policy)
    is recorded as not evaluated and cannot affect the decision --
    this makes "why didn't this rule fire" answerable by reading the
    result rather than needing to re-read the policy file.
    """
    results: list[RuleResult] = []
    decision = Decision.ALLOW

    for rule_name, check in _RULE_CHECKS.items():
        config = policy.rules.get(rule_name)
        enabled = config.enabled if config else False

        if not enabled:
            results.append(
                RuleResult(rule=rule_name, enabled=False, passed=True, action=None, message="not configured")
            )
            continue

        passed, message = check(context)
        action = config.on_fail if config else "deny"  # pragma: no branch -- config is set when enabled
        results.append(RuleResult(rule=rule_name, enabled=True, passed=passed, action=action, message=message))

        if passed:
            continue

        # Revocation is a special case: it always escalates to REVOKED
        # regardless of the configured on_fail action. Silently letting
        # a revoked model through with "on_fail: warn" would defeat the
        # entire purpose of revocation.
        triggered = Decision.REVOKED if rule_name == "reject_revoked_models" else ACTION_TO_DECISION[action]
        if triggered.severity > decision.severity:
            decision = triggered

    return PolicyDecisionResult(
        decision=decision,
        policy_name=policy.name,
        policy_version=policy.version,
        subject=context.subject,
        rule_results=tuple(results),
    )
