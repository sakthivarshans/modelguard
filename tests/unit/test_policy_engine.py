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
