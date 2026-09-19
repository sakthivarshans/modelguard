from __future__ import annotations

from modelguard.policy.engine import PolicyEvaluationContext, evaluate
from modelguard.policy.models import Decision, PolicyDocument, RuleConfig


def _context(**overrides: bool) -> PolicyEvaluationContext:
    defaults = {
        "subject": "demo@1.0.0",
        "signature_valid": True,
        "mbom_valid": True,
        "revoked": False,
        "has_license": True,
        "has_declared_lineage": True,
    }
    defaults.update(overrides)
    return PolicyEvaluationContext(**defaults)  # type: ignore[arg-type]


def test_all_rules_passing_allows(tmp_path=None) -> None:
    policy = PolicyDocument(
        name="strict",
        rules={
            "require_valid_signature": RuleConfig(enabled=True, on_fail="deny"),
            "require_ml_bom": RuleConfig(enabled=True, on_fail="deny"),
            "require_license": RuleConfig(enabled=True, on_fail="deny"),
            "require_known_lineage": RuleConfig(enabled=True, on_fail="deny"),
            "reject_revoked_models": RuleConfig(enabled=True, on_fail="deny"),
        },
    )
    result = evaluate(_context(), policy)

    assert result.decision == Decision.ALLOW
    assert result.failed_rules == ()


def test_no_rules_configured_allows() -> None:
    policy = PolicyDocument(name="empty")
    result = evaluate(_context(signature_valid=False), policy)

    assert result.decision == Decision.ALLOW  # rule not enabled -> can't fail


def test_disabled_rule_cannot_trigger_a_denial() -> None:
    policy = PolicyDocument(
        name="p", rules={"require_valid_signature": RuleConfig(enabled=False, on_fail="deny")}
    )
    result = evaluate(_context(signature_valid=False), policy)

    assert result.decision == Decision.ALLOW


def test_warn_on_fail_produces_allow_with_warnings() -> None:
    policy = PolicyDocument(
        name="p", rules={"require_license": RuleConfig(enabled=True, on_fail="warn")}
    )
    result = evaluate(_context(has_license=False), policy)

    assert result.decision == Decision.ALLOW_WITH_WARNINGS
    assert result.decision.is_allowed


def test_review_on_fail_produces_review_required() -> None:
    policy = PolicyDocument(
        name="p", rules={"require_known_lineage": RuleConfig(enabled=True, on_fail="review")}
    )
    result = evaluate(_context(has_declared_lineage=False), policy)

    assert result.decision == Decision.REVIEW_REQUIRED
    assert not result.decision.is_allowed


def test_quarantine_on_fail_produces_quarantine() -> None:
    policy = PolicyDocument(
        name="p", rules={"require_ml_bom": RuleConfig(enabled=True, on_fail="quarantine")}
    )
    result = evaluate(_context(mbom_valid=False), policy)

    assert result.decision == Decision.QUARANTINE


def test_deny_on_fail_produces_deny() -> None:
    policy = PolicyDocument(
        name="p", rules={"require_valid_signature": RuleConfig(enabled=True, on_fail="deny")}
    )
    result = evaluate(_context(signature_valid=False), policy)

    assert result.decision == Decision.DENY


def test_revocation_always_escalates_to_revoked_regardless_of_on_fail() -> None:
    """Even if a policy author mistakenly (or maliciously) configures
    reject_revoked_models with on_fail: warn, a revoked model must
    never be merely a warning.
    """
    policy = PolicyDocument(
        name="p", rules={"reject_revoked_models": RuleConfig(enabled=True, on_fail="warn")}
    )
    result = evaluate(_context(revoked=True), policy)

    assert result.decision == Decision.REVOKED
    assert not result.decision.is_allowed


def test_overall_decision_is_the_most_severe_triggered() -> None:
    policy = PolicyDocument(
        name="p",
        rules={
            "require_license": RuleConfig(enabled=True, on_fail="warn"),
            "require_valid_signature": RuleConfig(enabled=True, on_fail="deny"),
            "require_known_lineage": RuleConfig(enabled=True, on_fail="review"),
        },
    )
    result = evaluate(
        _context(has_license=False, signature_valid=False, has_declared_lineage=False), policy
    )

    # warn < review < deny in severity -- DENY must win.
    assert result.decision == Decision.DENY
    assert len(result.failed_rules) == 3


def test_evaluation_is_deterministic() -> None:
    policy = PolicyDocument(
        name="p",
        rules={
            "require_valid_signature": RuleConfig(enabled=True, on_fail="deny"),
            "require_license": RuleConfig(enabled=True, on_fail="warn"),
        },
    )
    ctx = _context(signature_valid=False, has_license=False)

    results = [evaluate(ctx, policy).decision for _ in range(10)]

    assert len(set(results)) == 1


def test_explain_lists_failed_rules_with_messages() -> None:
    policy = PolicyDocument(
        name="p", rules={"require_valid_signature": RuleConfig(enabled=True, on_fail="deny")}
    )
    result = evaluate(_context(signature_valid=False), policy)

    explanation = result.explain()

    assert "require_valid_signature" in explanation
    assert "DENY" in explanation


def test_explain_for_fully_passing_evaluation_is_reassuring_not_alarming() -> None:
    policy = PolicyDocument(
        name="p", rules={"require_valid_signature": RuleConfig(enabled=True, on_fail="deny")}
    )
    result = evaluate(_context(), policy)

    explanation = result.explain()

    assert "ALLOW" in explanation
    assert "Failed rule" not in explanation


# -- Phase 4: count-based rules (max_critical_findings, max_high_findings) --


def _scan_context(**overrides: object) -> PolicyEvaluationContext:
    defaults: dict[str, object] = {
        "subject": "demo@1.0.0",
        "signature_valid": True,
        "mbom_valid": True,
        "revoked": False,
        "has_license": True,
        "has_declared_lineage": True,
        "scan_performed": True,
        "critical_finding_count": 0,
        "high_finding_count": 0,
    }
    defaults.update(overrides)
    return PolicyEvaluationContext(**defaults)  # type: ignore[arg-type]


def test_max_critical_findings_enabled_but_no_scan_fails_closed() -> None:
    """Enabling this rule without ever running a scan must DENY, not
    silently treat "no scan" as "zero findings found".
    """
    policy = PolicyDocument(
        name="p",
        rules={"max_critical_findings": RuleConfig(enabled=True, on_fail="deny", max_count=0)},
    )
    result = evaluate(_scan_context(scan_performed=False), policy)

    assert result.decision == Decision.DENY
    assert any(r.rule == "max_critical_findings" for r in result.failed_rules)


def test_max_critical_findings_passes_when_scan_performed_and_within_limit() -> None:
    policy = PolicyDocument(
        name="p",
        rules={"max_critical_findings": RuleConfig(enabled=True, on_fail="deny", max_count=0)},
    )
    result = evaluate(_scan_context(scan_performed=True, critical_finding_count=0), policy)

    assert result.decision == Decision.ALLOW


def test_max_critical_findings_fails_when_count_exceeds_limit() -> None:
    policy = PolicyDocument(
        name="p",
        rules={"max_critical_findings": RuleConfig(enabled=True, on_fail="deny", max_count=0)},
    )
    result = evaluate(_scan_context(scan_performed=True, critical_finding_count=1), policy)

    assert result.decision == Decision.DENY
    assert any(r.rule == "max_critical_findings" for r in result.failed_rules)


def test_max_critical_findings_respects_a_nonzero_configured_limit() -> None:
    policy = PolicyDocument(
        name="p",
        rules={"max_critical_findings": RuleConfig(enabled=True, on_fail="deny", max_count=2)},
    )
    within_limit = evaluate(_scan_context(scan_performed=True, critical_finding_count=2), policy)
    over_limit = evaluate(_scan_context(scan_performed=True, critical_finding_count=3), policy)

    assert within_limit.decision == Decision.ALLOW
    assert over_limit.decision == Decision.DENY


def test_max_high_findings_enabled_but_no_scan_fails_closed() -> None:
    policy = PolicyDocument(
        name="p",
        rules={"max_high_findings": RuleConfig(enabled=True, on_fail="deny", max_count=0)},
    )
    result = evaluate(_scan_context(scan_performed=False), policy)

    assert result.decision == Decision.DENY
    assert any(r.rule == "max_high_findings" for r in result.failed_rules)


def test_max_high_findings_passes_within_limit_and_fails_over_limit() -> None:
    policy = PolicyDocument(
        name="p",
        rules={"max_high_findings": RuleConfig(enabled=True, on_fail="deny", max_count=1)},
    )
    within_limit = evaluate(_scan_context(scan_performed=True, high_finding_count=1), policy)
    over_limit = evaluate(_scan_context(scan_performed=True, high_finding_count=2), policy)

    assert within_limit.decision == Decision.ALLOW
    assert over_limit.decision == Decision.DENY


def test_count_based_rule_disabled_by_default_does_not_require_a_scan() -> None:
    """A policy that never enables the count-based rules must not be
    affected by scan_performed=False -- the fail-closed behavior only
    applies once the rule is actually enabled.
    """
    policy = PolicyDocument(
        name="p", rules={"require_valid_signature": RuleConfig(enabled=True, on_fail="deny")}
    )
    result = evaluate(_scan_context(scan_performed=False), policy)

    assert result.decision == Decision.ALLOW
