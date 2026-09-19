from __future__ import annotations

from modelguard.policy.engine import PolicyEvaluationContext, evaluate
from modelguard.policy.models import Decision, PolicyDocument, RuleConfig


def _ctx(**overrides: object) -> PolicyEvaluationContext:
    base: dict[str, object] = {
        "subject": "demo@1.0.0",
        "signature_valid": True,
        "mbom_valid": True,
        "revoked": False,
        "has_license": True,
        "has_declared_lineage": True,
        "artifact_digest_matches": True,
        "signer_trusted": True,
    }
    base.update(overrides)
    return PolicyEvaluationContext(**base)  # type: ignore[arg-type]


def _policy(**rules: RuleConfig) -> PolicyDocument:
    return PolicyDocument(name="t", rules=dict(rules))


def test_digest_mismatch_denies_even_with_no_rules() -> None:
    result = evaluate(_ctx(artifact_digest_matches=False), _policy())
    assert result.decision == Decision.DENY
    assert result.failed_rules[0].rule == "artifact_integrity"


def test_digest_mismatch_cannot_be_downgraded_by_any_rule_config() -> None:
    policy = _policy(require_valid_signature=RuleConfig(enabled=True, on_fail="warn"))
    assert evaluate(_ctx(artifact_digest_matches=False), policy).decision == Decision.DENY


def test_revoked_still_outranks_integrity_denial() -> None:
    policy = _policy(reject_revoked_models=RuleConfig(enabled=True))
    result = evaluate(_ctx(artifact_digest_matches=False, revoked=True), policy)
    assert result.decision == Decision.REVOKED


def test_unevaluated_digest_state_skips_the_gate_for_hand_built_contexts() -> None:
    # Documented compat behavior: None means "caller did not evaluate".
    assert evaluate(_ctx(artifact_digest_matches=None), _policy()).decision == Decision.ALLOW


def test_trusted_signer_passes() -> None:
    policy = _policy(require_trusted_signer=RuleConfig(enabled=True))
    assert evaluate(_ctx(signer_trusted=True), policy).decision == Decision.ALLOW


def test_untrusted_signer_fails_with_configured_action() -> None:
    policy = _policy(require_trusted_signer=RuleConfig(enabled=True, on_fail="review"))
    assert evaluate(_ctx(signer_trusted=False), policy).decision == Decision.REVIEW_REQUIRED


def test_trusted_signer_rule_fails_closed_when_no_trust_roots_configured() -> None:
    policy = _policy(require_trusted_signer=RuleConfig(enabled=True, on_fail="deny"))
    result = evaluate(_ctx(signer_trusted=None), policy)
    assert result.decision == Decision.DENY
    assert "no trusted signer keys were configured" in result.failed_rules[0].message
