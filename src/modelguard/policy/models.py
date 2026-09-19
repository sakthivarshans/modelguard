"""Policy data model.

A policy document is a small set of named boolean "require_*" rules,
each with an explicit action to take if it fails. Evaluation is a pure
function of a ``PolicyEvaluationContext`` (see ``modelguard.policy.engine``)
and the loaded ``PolicyDocument`` -- the same inputs always produce the
same decision, which is what "deterministic policy evaluation" means
in the project's requirements.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

POLICY_SCHEMA_VERSION = "1"

# Every rule ModelGuard knows how to evaluate. Deliberately smaller
# than the full rule set in the product document: rules that depend on
# data ModelGuard does not yet produce (risk classification, license
# allow-lists) are left out rather than accepted and silently ignored
# -- see docs/limitations.md. Phase 4 adds the two count-based rules;
# they were withheld in Phase 3 specifically because nothing produced
# a finding count to evaluate them against yet.
RuleName = Literal[
    "require_valid_signature",
    "require_ml_bom",
    "require_known_lineage",
    "require_license",
    "reject_revoked_models",
    "max_critical_findings",
    "max_high_findings",
]

KNOWN_RULE_NAMES: frozenset[str] = frozenset(
    {
        "require_valid_signature",
        "require_ml_bom",
        "require_known_lineage",
        "require_license",
        "reject_revoked_models",
        "max_critical_findings",
        "max_high_findings",
    }
)

# What happens when a rule fails. "reject_revoked_models" ignores this
# and always escalates to REVOKED -- see engine.py for why.
RuleAction = Literal["warn", "review", "quarantine", "deny"]


class Decision(str, Enum):
    """A policy decision, ordered from least to most severe.

    The ordering matters: when multiple rules fail with different
    actions, the overall decision is the *most* severe one triggered,
    never the least.
    """

    ALLOW = "ALLOW"
    ALLOW_WITH_WARNINGS = "ALLOW_WITH_WARNINGS"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    QUARANTINE = "QUARANTINE"
    DENY = "DENY"
    REVOKED = "REVOKED"

    @property
    def severity(self) -> int:
        return _SEVERITY[self]

    @property
    def is_allowed(self) -> bool:
        """Whether deployment may proceed without further human action.

        Only ALLOW and ALLOW_WITH_WARNINGS permit that; REVIEW_REQUIRED
        and QUARANTINE require a human decision even though they are
        less severe than DENY, so this is not simply "severity below
        DENY".
        """
        return self in (Decision.ALLOW, Decision.ALLOW_WITH_WARNINGS)


_SEVERITY: dict[Decision, int] = {
    Decision.ALLOW: 0,
    Decision.ALLOW_WITH_WARNINGS: 1,
    Decision.REVIEW_REQUIRED: 2,
    Decision.QUARANTINE: 3,
    Decision.DENY: 4,
    Decision.REVOKED: 5,
}

ACTION_TO_DECISION: dict[RuleAction, Decision] = {
    "warn": Decision.ALLOW_WITH_WARNINGS,
    "review": Decision.REVIEW_REQUIRED,
    "quarantine": Decision.QUARANTINE,
    "deny": Decision.DENY,
}


class RuleConfig(BaseModel):
    """Configuration for a single policy rule."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    enabled: bool = True
    on_fail: RuleAction = "deny"
    # Only meaningful for the count-based rules (max_critical_findings,
    # max_high_findings); ignored by the boolean rules. Kept on the
    # shared RuleConfig, rather than a rule-specific subclass, so the
    # YAML schema and PolicyDocument.rules stay a single uniform
    # mapping -- see policy/loader.py.
    max_count: int = Field(default=0, ge=0)


class PolicyDocument(BaseModel):
    """A loaded, schema-validated policy document."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    version: str = POLICY_SCHEMA_VERSION
    name: str
    environment: str | None = None
    rules: dict[str, RuleConfig] = Field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RuleResult:
    """The outcome of evaluating a single rule."""

    rule: str
    enabled: bool
    passed: bool
    action: RuleAction | None
    message: str


@dataclass(frozen=True, slots=True)
class PolicyDecisionResult:
    """The full, explainable outcome of a policy evaluation."""

    decision: Decision
    policy_name: str
    policy_version: str
    subject: str
    rule_results: tuple[RuleResult, ...]
    evaluation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    @property
    def failed_rules(self) -> tuple[RuleResult, ...]:
        return tuple(r for r in self.rule_results if r.enabled and not r.passed)

    def explain(self) -> str:
        """A human-readable explanation, in the style the architecture
        document specifies: which rule failed, what was expected, and
        how the caller can fix it -- not a bare "something went wrong".
        """
        if self.decision.is_allowed and not self.failed_rules:
            return f"{self.subject}: {self.decision.value} -- all enabled rules passed."

        lines = [f"{self.subject}: {self.decision.value}", ""]
        for r in self.failed_rules:
            lines.append(f"Failed rule: {r.rule}")
            lines.append(f"  {r.message}")
        return "\n".join(lines)
