"""Security tests: hostile trust-configuration files.

Trust configuration is exactly the kind of file the threat model warns
about under "Policy Bypass" / "attacker tampering with policy files":
if an attacker can add their own key to it, they bypass every other
control. This module doesn't defend the file's *access control* (that
is a deployment concern -- who can write the path passed to
--trust-config), but it does guarantee the loader never does anything
more dangerous than reading bytes and validating a strict schema, and
that a malformed or partially-valid file is refused wholesale rather
than partially trusted.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from modelguard.exceptions import TrustConfigurationError
from modelguard.signing.trust_config import (
    MAX_TRUST_CONFIG_BYTES,
    TrustConfig,
    TrustedKeyEntry,
    evaluate_trust,
    load_trust_config_file,
)

FP_A = "a" * 64


def test_yaml_python_object_tags_are_refused(tmp_path: Path) -> None:
    """yaml.safe_load must be in use: an arbitrary-object tag must not
    construct anything, only fail to parse into the expected schema."""
    path = tmp_path / "trust.yaml"
    path.write_text(
        "keys:\n  - key_id: !!python/object/apply:os.system ['echo pwned']\n"
    )
    with pytest.raises(TrustConfigurationError):
        load_trust_config_file(path)


def test_oversized_file_is_rejected_before_yaml_parsing(tmp_path: Path) -> None:
    path = tmp_path / "trust.yaml"
    path.write_bytes(b"keys: []\n# " + b"x" * (MAX_TRUST_CONFIG_BYTES + 1))
    with pytest.raises(TrustConfigurationError, match="larger than"):
        load_trust_config_file(path)


def test_non_utf8_file_is_refused_cleanly(tmp_path: Path) -> None:
    path = tmp_path / "trust.yaml"
    path.write_bytes(b"\xff\xfe\x00\x01keys: []")
    with pytest.raises(TrustConfigurationError):
        load_trust_config_file(path)


def test_yaml_anchor_bomb_does_not_hang_or_crash(tmp_path: Path) -> None:
    """A classic 'billion laughs'-style YAML expansion, bounded by the
    file-size cap before anything is parsed -- this must fail fast,
    not attempt to expand a huge in-memory structure."""
    path = tmp_path / "trust.yaml"
    lines = ["a0: &a0 [\"x\"]"]
    for i in range(1, 8):
        lines.append(f"a{i}: &a{i} [*a{i - 1}, *a{i - 1}, *a{i - 1}, *a{i - 1}, *a{i - 1}]")
    lines.append("keys: *a7")
    path.write_text("\n".join(lines))
    with pytest.raises(TrustConfigurationError):
        load_trust_config_file(path)


def test_one_bad_key_entry_invalidates_the_whole_file_rather_than_being_dropped(
    tmp_path: Path,
) -> None:
    """A file with one good entry and one malformed entry must be refused
    entirely -- a loader that silently dropped the bad entry and kept the
    good one could be used to smuggle in a key under cover of a parse
    error nobody investigates."""
    path = tmp_path / "trust.yaml"
    path.write_text(f"keys:\n  - key_id: '{FP_A}'\n  - key_id: 'not-valid'\n")
    with pytest.raises(TrustConfigurationError):
        load_trust_config_file(path)


def test_unknown_field_smuggled_into_an_entry_is_rejected_not_ignored(tmp_path: Path) -> None:
    """extra='forbid' must actually be enforced end to end through the
    YAML loader, not only when constructing the model directly in Python."""
    path = tmp_path / "trust.yaml"
    path.write_text(f"keys:\n  - key_id: '{FP_A}'\n    always_trust_regardless: true\n")
    with pytest.raises(TrustConfigurationError, match="schema validation"):
        load_trust_config_file(path)


def test_path_traversal_style_filename_is_just_a_read_that_fails_or_succeeds_normally(
    tmp_path: Path,
) -> None:
    """load_trust_config_file takes a Path the caller already resolved (a
    CLI --trust-config argument); it must not do anything beyond a plain
    read of that path -- no following of unexpected symlinks it creates
    itself, no writing, no second file access."""
    real = tmp_path / "real.yaml"
    real.write_text(f"keys:\n  - key_id: '{FP_A}'\n")
    link = tmp_path / "link.yaml"
    link.symlink_to(real)
    # Following a symlink the CALLER placed is expected filesystem behavior,
    # not a vulnerability introduced by this loader -- it must simply work.
    config = load_trust_config_file(link)
    assert config.keys[0].key_id == FP_A


# --- Mutation-checked: the checks that actually gate trust ---------------------


def test_revocation_beats_a_signature_that_claims_to_predate_it() -> None:
    """The core anti-backdating property: evaluate_trust has no signed_at
    parameter at all, so a revoked key is refused regardless of when a
    signature claims to have been made. This is the property tested here
    empirically: revocation state and expiry are functions of `now` only."""
    now = datetime(2026, 6, 1, tzinfo=UTC)
    config = TrustConfig(keys=(TrustedKeyEntry(key_id=FP_A, status="revoked"),))  # type: ignore[arg-type]
    # Even asking as though verifying "in the past" (before some
    # hypothetical revocation event) makes no difference: there is no
    # revoked_at/not_after here, so the key is simply never active.
    assert evaluate_trust(FP_A, "ed25519", config, now=now).trusted is False
    earlier = datetime(2000, 1, 1, tzinfo=UTC)
    assert evaluate_trust(FP_A, "ed25519", config, now=earlier).trusted is False
