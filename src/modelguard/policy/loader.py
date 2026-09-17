"""Safe policy loading.

Security rule (see threat model, "Policy Bypass"): policy files are
untrusted input -- they may come from a repository an attacker has
partial control over. This module therefore:

  - Uses ``yaml.safe_load`` exclusively. ``yaml.load`` with the
    default loader can construct arbitrary Python objects from a
    crafted YAML file and must never be used here.
  - Validates the result against a strict schema (``extra="forbid"``
    on every model), so an unrecognized field fails loudly instead of
    being silently ignored.
  - Rejects unknown rule names explicitly, rather than accepting and
    ignoring them -- a typo'd or renamed rule that silently evaluates
    to "no rule configured, so it can't fail" is a policy-bypass risk.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from modelguard.exceptions import ModelGuardError
from modelguard.policy.models import KNOWN_RULE_NAMES, PolicyDocument


class PolicyValidationError(ModelGuardError):
    """A policy file is malformed, or fails schema validation."""


class UnknownRuleError(PolicyValidationError):
    """A policy file references a rule ModelGuard does not implement."""

    def __init__(self, rule_name: str) -> None:
        self.rule_name = rule_name
        super().__init__(
            f"Unknown policy rule {rule_name!r}. Known rules: "
            f"{sorted(KNOWN_RULE_NAMES)}. Refusing to load a policy with an "
            "unrecognized rule rather than silently ignoring it."
        )


def load_policy_file(path: Path) -> PolicyDocument:
    """Load and validate a policy YAML file.

    Raises ``PolicyValidationError`` (or the more specific
    ``UnknownRuleError``) for any malformed or unrecognized input.
    Never raises a bare ``yaml.YAMLError`` or ``pydantic.ValidationError``
    to the caller, so callers can catch one exception type.
    """
    if not path.exists():
        raise PolicyValidationError(f"Policy file not found: {path}")

    try:
        raw = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        raise PolicyValidationError(f"Policy file is not valid YAML: {exc}") from exc

    if not isinstance(raw, dict):
        raise PolicyValidationError(
            "Policy file must be a YAML mapping with 'policy' and 'rules' keys."
        )

    return parse_policy_document(raw)


def parse_policy_document(raw: dict[str, Any]) -> PolicyDocument:
    """Validate an already-parsed policy mapping (used by the loader,
    and directly by tests / the policy-simulation CLI command).
    """
    unknown_top_level = set(raw) - {"version", "policy", "rules"}
    if unknown_top_level:
        raise PolicyValidationError(
            f"Unknown top-level field(s): {sorted(unknown_top_level)}. "
            "Allowed: version, policy, rules."
        )

    policy_section = raw.get("policy")
    rules_section = raw.get("rules", {})

    if not isinstance(policy_section, dict) or "name" not in policy_section:
        raise PolicyValidationError(
            "Policy file must have a 'policy:' section with at least a 'name' field."
        )
    if not isinstance(rules_section, dict):
        raise PolicyValidationError("Policy file's 'rules:' section must be a mapping.")

    unknown_policy_fields = set(policy_section) - {"name", "environment"}
    if unknown_policy_fields:
        raise PolicyValidationError(
            f"Unknown field(s) in 'policy:' section: {sorted(unknown_policy_fields)}. "
            "Allowed fields: name, environment."
        )

    for rule_name in rules_section:
        if rule_name not in KNOWN_RULE_NAMES:
            raise UnknownRuleError(rule_name)

    try:
        return PolicyDocument(
            version=str(raw.get("version", "1")),
            name=policy_section["name"],
            environment=policy_section.get("environment"),
            rules=rules_section,
        )
    except Exception as exc:  # pydantic.ValidationError, narrowed to our type
        raise PolicyValidationError(f"Policy file failed schema validation: {exc}") from exc
