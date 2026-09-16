from __future__ import annotations

import os
from pathlib import Path

import pytest

from modelguard.exceptions import (
    ArtifactNotFoundError,
    EmptyArtifactError,
    UnsafePathError,
)
from modelguard.hashing.digest import hash_artifact, hash_directory, hash_file


def test_hash_file_is_deterministic(tmp_path: Path) -> None:
    f = tmp_path / "weights.bin"
    f.write_bytes(b"hello model weights")

    d1 = hash_file(f)
    d2 = hash_file(f)

    assert d1.digest == d2.digest
    assert d1.artifact_type == "file"
    assert d1.algorithm == "sha256"


def test_hash_file_changes_when_content_changes(tmp_path: Path) -> None:
    f = tmp_path / "weights.bin"
    f.write_bytes(b"version one")
    d1 = hash_file(f)

    f.write_bytes(b"version two")
    d2 = hash_file(f)

    assert d1.digest != d2.digest


def test_hash_directory_is_deterministic(tmp_path: Path) -> None:
    root = tmp_path / "model"
    root.mkdir()
    (root / "config.json").write_text('{"a": 1}')
    (root / "weights.safetensors").write_bytes(b"\x00\x01\x02")
    sub = root / "tokenizer"
    sub.mkdir()
    (sub / "vocab.txt").write_text("hello\nworld\n")

    d1 = hash_directory(root)
    d2 = hash_directory(root)

    assert d1.digest == d2.digest
    assert d1.artifact_type == "directory"
    assert len(d1.files) == 3


def test_hash_directory_independent_of_walk_order(tmp_path: Path) -> None:
    """Two directories with the same files, created in different
    orders, must produce the same digest -- enumeration is sorted.
    """
    root_a = tmp_path / "a"
    root_a.mkdir()
    (root_a / "b.txt").write_text("b")
    (root_a / "a.txt").write_text("a")

    root_b = tmp_path / "b"
    root_b.mkdir()
    (root_b / "a.txt").write_text("a")
    (root_b / "b.txt").write_text("b")

    assert hash_directory(root_a).digest == hash_directory(root_b).digest


def test_hash_directory_changes_when_a_file_is_added(tmp_path: Path) -> None:
    root = tmp_path / "model"
    root.mkdir()
    (root / "config.json").write_text("{}")
    d1 = hash_directory(root)

    (root / "extra.txt").write_text("surprise")
    d2 = hash_directory(root)

    assert d1.digest != d2.digest


def test_hash_directory_changes_when_a_file_is_renamed(tmp_path: Path) -> None:
    """Digest must depend on path, not only content -- otherwise a
    file swap that preserves content set but changes structure would
    go undetected.
    """
    root = tmp_path / "model"
    root.mkdir()
    (root / "a.bin").write_bytes(b"same content")
    d1 = hash_directory(root)

    (root / "a.bin").rename(root / "b.bin")
    d2 = hash_directory(root)

    assert d1.digest != d2.digest


def test_hash_directory_ignores_file_timestamps(tmp_path: Path) -> None:
    root = tmp_path / "model"
    root.mkdir()
    f = root / "weights.bin"
    f.write_bytes(b"abc")
    d1 = hash_directory(root)

    # Change mtime without changing content.
    future = 2_000_000_000
    os.utime(f, (future, future))
    d2 = hash_directory(root)

    assert d1.digest == d2.digest


def test_hash_empty_directory_raises(tmp_path: Path) -> None:
    root = tmp_path / "empty"
    root.mkdir()
    with pytest.raises(EmptyArtifactError):
        hash_directory(root)


def test_hash_missing_path_raises(tmp_path: Path) -> None:
    with pytest.raises(ArtifactNotFoundError):
        hash_artifact(tmp_path / "does-not-exist")


def test_hash_artifact_dispatches_to_file_and_directory(tmp_path: Path) -> None:
    f = tmp_path / "single.bin"
    f.write_bytes(b"x")
    assert hash_artifact(f).artifact_type == "file"

    d = tmp_path / "dir"
    d.mkdir()
    (d / "x.bin").write_bytes(b"x")
    assert hash_artifact(d).artifact_type == "directory"


@pytest.mark.skipif(os.name == "nt", reason="symlinks require special privileges on Windows")
def test_symlinked_file_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "model"
    root.mkdir()
    real = tmp_path / "real.bin"
    real.write_bytes(b"data")
    (root / "link.bin").symlink_to(real)

    with pytest.raises(UnsafePathError):
        hash_directory(root)


@pytest.mark.skipif(os.name == "nt", reason="symlinks require special privileges on Windows")
def test_directory_symlink_escaping_root_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "model"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.bin").write_bytes(b"secret")
    (root / "escape").symlink_to(outside)

    with pytest.raises(UnsafePathError):
        hash_directory(root)


@pytest.mark.skipif(os.name == "nt", reason="symlinks require special privileges on Windows")
def test_symlinked_artifact_root_is_rejected(tmp_path: Path) -> None:
    real = tmp_path / "real_model"
    real.mkdir()
    (real / "a.bin").write_bytes(b"x")
    link = tmp_path / "link_model"
    link.symlink_to(real)

    with pytest.raises(UnsafePathError):
        hash_artifact(link)
