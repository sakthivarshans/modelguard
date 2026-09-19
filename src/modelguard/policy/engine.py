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
    RuleConfig,
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
    # Phase 4: scanner-derived facts. ``scan_performed`` defaults to
    # False so any context built without the new keyword arguments
    # (e.g. an older caller, or a test written before Phase 4)
    # continues to behave exactly as it did in Phase 3 for the two new
    # rules: enabling either of them without ever running a scan fails
    # closed rather than silently passing -- see the two _check_max_*
    # functions below.
    scan_performed: bool = False
    critical_finding_count: int = 0
    high_finding_count: int = 0
    # Phase 5: whether the artifact on disk matched the digest bound in
    # the signature, and whether the signing key is in the caller's
    # explicit trust roots.
    #
    # ``artifact_digest_matches`` is an UNCONDITIONAL integrity gate,
    # not a rule: ``False`` always yields DENY, whatever the policy
    # says (see ``evaluate``). ``None`` means "not evaluated" and skips
    # the gate -- it exists only so hand-built contexts written before
    # Phase 5 keep working; ``build_context`` (the trusted path)
    # requires the value explicitly.
    #
    # ``signer_trusted`` is ``None`` when no trust roots were
    # configured at all; ``require_trusted_signer`` fails closed on
    # ``None`` rather than treating "nothing configured" as "trusted".
    artifact_digest_matches: bool | None = None
    signer_trusted: bool | None = None


def build_context(
    manifest: Manifest,
    mbom: MLBOM,
    *,
    signature_valid: bool,
    mbom_valid: bool,
    revoked: bool,
    artifact_digest_matches: bool,
    scan_performed: bool = False,
    critical_finding_count: int = 0,
    high_finding_count: int = 0,
    signer_trusted: bool | None = None,
) -> PolicyEvaluationContext:
    """Build a context from a manifest, ML-BOM, and the boolean/count
    results already computed by ``ModelGuard.verify()`` and
    ``ModelGuard.scan()``.
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
        scan_performed=scan_performed,
        critical_finding_count=critical_finding_count,
        high_finding_count=high_finding_count,
        artifact_digest_matches=artifact_digest_matches,
        signer_trusted=signer_trusted,
    )


def _check_require_valid_signature(
    ctx: PolicyEvaluationContext, config: RuleConfig
) -> tuple[bool, str]:
    if ctx.signature_valid:
        return True, "A valid signature was found."
    return False, (
        "No valid signature was found. Expected: a signature verifiable against a "
        "known public key. Suggested action: sign the artifact with `modelguard sign` "
        "before registering or deploying it."
    )


def _check_require_trusted_signer(
    ctx: PolicyEvaluationContext, config: RuleConfig
) -> tuple[bool, str]:
    # Fail closed on "not configured": a valid signature from an
    # unknown key proves nothing about who signed -- anyone can sign
    # with a key they just generated. Enabling this rule without
    # supplying trust roots must not quietly pass.
    if ctx.signer_trusted is None:
        return False, (
            "require_trusted_signer is enabled but no trusted signer keys were configured. "
            "Expected: at least one trusted key fingerprint. Suggested action: pass "
            "--trusted-fingerprint (CLI) or trusted_key_fingerprints=[...] (SDK); compute a "
            "fingerprint with `modelguard fingerprint <public-key-file>`."
        )
    if ctx.signer_trusted:
        return True, "The artifact was signed by a trusted key."
    return False, (
        "The signing key is not in the configured trusted set. Expected: a signature "
        "made by one of the trusted key fingerprints. Suggested action: verify the "
        "signer out-of-band, then add its fingerprint to the trusted set, or obtain the "
        "artifact from a trusted publisher."
    )


def _check_require_ml_bom(ctx: PolicyEvaluationContext, config: RuleConfig) -> tuple[bool, str]:
    if ctx.mbom_valid:
        return True, "A matching ML-BOM was supplied."
    return False, (
        "No valid ML-BOM was supplied, or it does not match the signed digest. "
        "Expected: an ML-BOM generated with `modelguard mbom generate` and bound to "
        "this artifact's signature. Suggested action: regenerate and re-sign."
    )


def _check_require_known_lineage(
    ctx: PolicyEvaluationContext, config: RuleConfig
) -> tuple[bool, str]:
    if ctx.has_declared_lineage:
        return True, "The ML-BOM declares at least one parent model."
    return False, (
        "The ML-BOM does not declare any parent model. Expected: at least one "
        "parent_models entry. Suggested action: regenerate the ML-BOM with "
        "DeclaredProvenance(parent_models=[...])."
    )


def _check_require_license(ctx: PolicyEvaluationContext, config: RuleConfig) -> tuple[bool, str]:
    if ctx.has_license:
        return True, "A license is declared."
    return False, (
        "No license is declared on the manifest or ML-BOM. Expected: a license "
        "identifier. Suggested action: re-run `modelguard manifest --license ...`."
    )


def _check_reject_revoked_models(
    ctx: PolicyEvaluationContext, config: RuleConfig
) -> tuple[bool, str]:
    if not ctx.revoked:
        return True, "The model is not revoked."
    return False, "The model has been revoked."


def _check_max_critical_findings(
    ctx: PolicyEvaluationContext, config: RuleConfig
) -> tuple[bool, str]:
    # Fail closed: a rule that is enabled but has no scan to check
    # against must NOT silently pass as if zero findings were found.
    # Silently treating "no scan ran" as "zero findings" would be
    # exactly the kind of fake completeness the project's engineering
    # rules forbid -- a policy author who enables this rule is asking
    # for scan-backed evidence, and none exists yet.
    if not ctx.scan_performed:
        return False, (
            "max_critical_findings is enabled but no scan was performed. Expected: a "
            "scan report to check finding counts against. Suggested action: ensure "
            "ModelGuard.check_policy() (which always scans) is used, or otherwise pass "
            "scan_performed=True with real finding counts to build_context()."
        )
    if ctx.critical_finding_count <= config.max_count:
        return True, (
            f"{ctx.critical_finding_count} CRITICAL finding(s) found, "
            f"within the configured limit of {config.max_count}."
        )
    return False, (
        f"{ctx.critical_finding_count} CRITICAL finding(s) found, exceeding the "
        f"configured limit of {config.max_count}. Expected: at most {config.max_count} "
        "CRITICAL findings. Suggested action: run `modelguard scan` and remediate the "
        "reported findings before re-registering or deploying."
    )


def _check_max_high_findings(ctx: PolicyEvaluationContext, config: RuleConfig) -> tuple[bool, str]:
    if not ctx.scan_performed:
        return False, (
            "max_high_findings is enabled but no scan was performed. Expected: a scan "
            "report to check finding counts against. Suggested action: ensure "
            "ModelGuard.check_policy() (which always scans) is used, or otherwise pass "
            "scan_performed=True with real finding counts to build_context()."
        )
    if ctx.high_finding_count <= config.max_count:
        return True, (
            f"{ctx.high_finding_count} HIGH finding(s) found, "
            f"within the configured limit of {config.max_count}."
        )
    return False, (
        f"{ctx.high_finding_count} HIGH finding(s) found, exceeding the configured "
        f"limit of {config.max_count}. Expected: at most {config.max_count} HIGH "
        "findings. Suggested action: run `modelguard scan` and remediate the reported "
        "findings before re-registering or deploying."
    )


_RULE_CHECKS: dict[str, Callable[[PolicyEvaluationContext, RuleConfig], tuple[bool, str]]] = {
    "require_valid_signature": _check_require_valid_signature,
    "require_trusted_signer": _check_require_trusted_signer,
    "require_ml_bom": _check_require_ml_bom,
    "require_known_lineage": _check_require_known_lineage,
    "require_license": _check_require_license,
    "reject_revoked_models": _check_reject_revoked_models,
    "max_critical_findings": _check_max_critical_findings,
    "max_high_findings": _check_max_high_findings,
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

    # Unconditional integrity gate. A cryptographically valid signature
    # says nothing about the artifact in front of us unless its digest
    # matches what was signed; before this gate existed, a tampered
    # artifact passed every policy that did not happen to check it
    # (see CHANGELOG 0.5.0). This is deliberately NOT a configurable
    # rule: no policy should be able to opt into deploying bytes that
    # differ from what was signed.
    if context.artifact_digest_matches is False:
        results.append(
            RuleResult(
                rule="artifact_integrity",
                enabled=True,
                passed=False,
                action="deny",
                message=(
                    "The artifact on disk does not match the digest bound in the signature: "
                    "it may have been modified after signing, or the wrong signature/ML-BOM "
                    "was supplied. This check is unconditional and cannot be disabled by "
                    "policy. Suggested action: re-obtain the artifact from a trusted source, "
                    "or re-sign it if the change was intentional."
                ),
            )
        )
        decision = Decision.DENY

    for rule_name, check in _RULE_CHECKS.items():
        config = policy.rules.get(rule_name)
        enabled = config.enabled if config else False

        if not enabled:
            results.append(
                RuleResult(rule=rule_name, enabled=False, passed=True, action=None, message="not configured")
            )
            continue

        assert config is not None  # enabled implies config was found above
        passed, message = check(context, config)
        action = config.on_fail
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
