"""Security tests: path traversal, symlink escape, and unsafe artifact
handling. See docs/security/threat-model.md, "Path Traversal".
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from modelguard.exceptions import UnsafePathError
from modelguard.hashing.digest import hash_directory


@pytest.mark.skipif(os.name == "nt", reason="symlinks require special privileges on Windows")
def test_nested_symlink_traversal_is_rejected(tmp_path: Path) -> None:
    """An attacker-controlled model directory contains a symlink several
    levels deep that points outside the artifact root. This must be
    rejected rather than silently hashing the linked-to file (which
    could be a secret elsewhere on the host) or silently skipping it
    (which could hide a tampered file from the digest).
    """
    root = tmp_path / "model"
    (root / "a" / "b").mkdir(parents=True)
    secret = tmp_path / "host_secret.txt"
    secret.write_text("private data outside the artifact")
    (root / "a" / "b" / "link.bin").symlink_to(secret)

    with pytest.raises(UnsafePathError):
        hash_directory(root)


@pytest.mark.skipif(os.name == "nt", reason="symlinks require special privileges on Windows")
def test_symlink_pointing_to_sibling_inside_root_still_rejected(tmp_path: Path) -> None:
    """Even a symlink that happens to resolve *inside* the artifact root
    is rejected in Phase 1. Silently allowing "safe" symlinks would
    require resolving every link and re-checking on each verification,
    adding complexity for a feature no MVP format requires.
    """
    root = tmp_path / "model"
    root.mkdir()
    (root / "weights.bin").write_bytes(b"data")
    (root / "weights_alias.bin").symlink_to(root / "weights.bin")

    with pytest.raises(UnsafePathError):
        hash_directory(root)


def test_artifact_root_must_exist(tmp_path: Path) -> None:
    from modelguard.exceptions import ArtifactNotFoundError

    with pytest.raises(ArtifactNotFoundError):
        hash_directory(tmp_path / "nonexistent")
