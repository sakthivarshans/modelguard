from __future__ import annotations

from pathlib import Path

import pytest

from modelguard.policy.loader import PolicyValidationError, UnknownRuleError, load_policy_file


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(text)
    return path


def test_load_valid_policy(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
        version: "1"
        policy:
          name: production-default
          environment: production
        rules:
          require_valid_signature:
            enabled: true
            on_fail: deny
          require_license:
            enabled: true
            on_fail: warn
        """,
    )

    doc = load_policy_file(path)

    assert doc.name == "production-default"
    assert doc.environment == "production"
    assert doc.rules["require_valid_signature"].enabled is True
    assert doc.rules["require_license"].on_fail == "warn"


def test_load_policy_defaults_rules_to_empty(tmp_path: Path) -> None:
    path = _write(tmp_path, "policy:\n  name: minimal\n")
    doc = load_policy_file(path)
    assert doc.rules == {}


def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(PolicyValidationError):
        load_policy_file(tmp_path / "nope.yaml")


def test_malformed_yaml_raises(tmp_path: Path) -> None:
    path = _write(tmp_path, "policy: [this is not: a valid mapping")
    with pytest.raises(PolicyValidationError):
        load_policy_file(path)


def test_missing_policy_section_raises(tmp_path: Path) -> None:
    path = _write(tmp_path, "rules:\n  require_valid_signature:\n    enabled: true\n")
    with pytest.raises(PolicyValidationError):
        load_policy_file(path)


def test_missing_policy_name_raises(tmp_path: Path) -> None:
    path = _write(tmp_path, "policy:\n  environment: production\n")
    with pytest.raises(PolicyValidationError):
        load_policy_file(path)


def test_unknown_rule_name_raises(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
        policy:
          name: bad
        rules:
          this_rule_does_not_exist:
            enabled: true
        """,
    )
    with pytest.raises(UnknownRuleError):
        load_policy_file(path)


def test_invalid_on_fail_value_raises(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
        policy:
          name: bad
        rules:
          require_valid_signature:
            enabled: true
            on_fail: nuke_from_orbit
        """,
    )
    with pytest.raises(PolicyValidationError):
        load_policy_file(path)


def test_unknown_top_level_field_is_ignored_gracefully(tmp_path: Path) -> None:
    """Fields outside the recognized policy/rules structure (e.g. stray
    top-level YAML keys) do not silently change behavior -- extra
    fields inside 'policy:' itself, however, are rejected by the
    strict PolicyDocument schema.
    """
    path = _write(
        tmp_path,
        """
        policy:
          name: strict
          not_a_real_field: true
        """,
    )
    with pytest.raises(PolicyValidationError):
        load_policy_file(path)


# --------------------------------------------------------------------------
# Security tests: unsafe YAML must never be executed
# --------------------------------------------------------------------------


def test_yaml_tag_object_construction_is_rejected(tmp_path: Path) -> None:
    """A malicious policy file attempting to use YAML tags to construct
    arbitrary Python objects (the classic yaml.load() RCE vector) must
    fail to load rather than succeed with a mysteriously wrong type.
    ``yaml.safe_load`` refuses the tag outright.
    """
    path = _write(
        tmp_path,
        """
        policy:
          name: !!python/object/apply:builtins.dict {}
        """,
    )
    with pytest.raises(PolicyValidationError):
        load_policy_file(path)


def test_example_policies_all_load(tmp_path: Path) -> None:
    """The example policies shipped in examples/policies/ must
    themselves be valid, or they are actively misleading documentation.
    """
    repo_root = Path(__file__).resolve().parents[2]
    examples_dir = repo_root / "examples" / "policies"
    example_files = list(examples_dir.glob("*.yaml"))
    assert example_files, "expected at least one example policy file"

    for path in example_files:
        doc = load_policy_file(path)
        assert doc.name
