from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from modelguard.cache import CachedHasher
from modelguard.cache import digest_cache as dc
from modelguard.hashing.digest import hash_artifact

posix_only = pytest.mark.skipif(os.name != "posix", reason="cache is bypassed off POSIX")


def _age(path: Path, seconds: int = 60) -> None:
    """Backdate mtime; ctime can't be backdated, so tests shrink the margin instead."""
    t = time.time() - seconds
    os.utime(path, (t, t))


@pytest.fixture(autouse=True)
def _no_racy_margin(monkeypatch: pytest.MonkeyPatch) -> None:
    # Files created by a test are "brand new"; with the real 2s margin nothing
    # would ever be cached. Tests that exercise the margin restore it.
    monkeypatch.setattr(dc, "RACY_MARGIN_NS", 0)


def _dir_model(root: Path) -> Path:
    model = root / "m"
    model.mkdir()
    (model / "a.bin").write_bytes(b"aaaa")
    (model / "sub").mkdir()
    (model / "sub" / "b.bin").write_bytes(b"bbbb")
    return model


@posix_only
def test_second_hash_is_a_cache_hit_with_identical_digest(tmp_path: Path) -> None:
    model = _dir_model(tmp_path)
    hasher = CachedHasher(tmp_path / "cache")

    first = hasher.hash(model)
    time.sleep(0.01)
    second = hasher.hash(model)

    assert not first.from_cache
    assert second.from_cache
    assert second.digest == first.digest == hash_artifact(model)


@posix_only
def test_cache_hit_also_works_for_a_single_file(tmp_path: Path) -> None:
    f = tmp_path / "w.safetensors"
    f.write_bytes(b"x" * 1000)
    hasher = CachedHasher(tmp_path / "cache")
    hasher.hash(f)
    again = hasher.hash(f)
    assert again.from_cache and again.digest == hash_artifact(f)


@posix_only
def test_content_change_same_size_invalidates(tmp_path: Path) -> None:
    model = _dir_model(tmp_path)
    hasher = CachedHasher(tmp_path / "cache")
    original = hasher.hash(model).digest

    (model / "a.bin").write_bytes(b"AAAA")  # same size, different bytes
    after = hasher.hash(model)

    assert not after.from_cache
    assert after.digest != original
    assert after.digest == hash_artifact(model)


@posix_only
def test_restoring_mtime_does_not_hide_an_edit(tmp_path: Path) -> None:
    """An attacker edits a file and resets mtime; ctime still advances."""
    model = _dir_model(tmp_path)
    hasher = CachedHasher(tmp_path / "cache")
    hasher.hash(model)

    target = model / "a.bin"
    before = target.stat()
    target.write_bytes(b"EVIL")
    os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))  # forge mtime back

    after = hasher.hash(model)
    assert not after.from_cache
    assert after.digest == hash_artifact(model)


@posix_only
def test_added_and_removed_files_invalidate(tmp_path: Path) -> None:
    model = _dir_model(tmp_path)
    hasher = CachedHasher(tmp_path / "cache")
    hasher.hash(model)

    (model / "extra.bin").write_bytes(b"new")
    assert not hasher.hash(model).from_cache
    hasher.hash(model)  # re-cache
    (model / "extra.bin").unlink()
    assert not hasher.hash(model).from_cache


@posix_only
def test_recently_modified_files_are_not_cached(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dc, "RACY_MARGIN_NS", 60 * 1_000_000_000)  # files are "too fresh"
    model = _dir_model(tmp_path)
    hasher = CachedHasher(tmp_path / "cache")
    hasher.hash(model)
    assert not hasher.hash(model).from_cache
    assert not hasher.cache_file.exists()


@posix_only
def test_symlink_in_artifact_is_never_cached_and_still_raises(tmp_path: Path) -> None:
    from modelguard.exceptions import UnsafePathError

    model = _dir_model(tmp_path)
    (model / "link").symlink_to(tmp_path / "outside")
    hasher = CachedHasher(tmp_path / "cache")
    with pytest.raises(UnsafePathError):
        hasher.hash(model)
    assert not hasher.cache_file.exists()


@posix_only
def test_symlink_added_after_caching_is_still_rejected(tmp_path: Path) -> None:
    from modelguard.exceptions import UnsafePathError

    model = _dir_model(tmp_path)
    hasher = CachedHasher(tmp_path / "cache")
    hasher.hash(model)
    (model / "sneaky").symlink_to(model / "a.bin")
    with pytest.raises(UnsafePathError):
        hasher.hash(model)


@posix_only
@pytest.mark.parametrize(
    "corruption",
    [b"not json", b"{}", b'{"schema_version": 99, "entries": {}}', b'{"schema_version": 1, "entries": {"k": 1}}'],
)
def test_corrupt_cache_file_is_a_miss_not_an_error(tmp_path: Path, corruption: bytes) -> None:
    model = _dir_model(tmp_path)
    hasher = CachedHasher(tmp_path / "cache")
    hasher.hash(model)
    hasher.cache_file.write_bytes(corruption)
    hasher.cache_file.chmod(0o600)

    result = hasher.hash(model)
    assert not result.from_cache
    assert result.digest == hash_artifact(model)


@posix_only
def test_forged_inconsistent_entry_is_rejected(tmp_path: Path) -> None:
    model = _dir_model(tmp_path)
    hasher = CachedHasher(tmp_path / "cache")
    hasher.hash(model)

    data = json.loads(hasher.cache_file.read_text())
    entry = next(iter(data["entries"].values()))
    entry["files"][0]["size"] += 1  # file list no longer matches recorded stats
    hasher.cache_file.write_text(json.dumps(data))
    hasher.cache_file.chmod(0o600)

    assert not hasher.hash(model).from_cache


@posix_only
def test_cache_file_is_created_private(tmp_path: Path) -> None:
    model = _dir_model(tmp_path)
    hasher = CachedHasher(tmp_path / "cache")
    hasher.hash(model)
    assert (hasher.cache_file.stat().st_mode & 0o777) == 0o600


@posix_only
def test_entry_count_is_bounded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dc, "MAX_ENTRIES", 3)
    hasher = CachedHasher(tmp_path / "cache")
    for i in range(6):
        f = tmp_path / f"f{i}.bin"
        f.write_bytes(bytes([i]) * 10)
        hasher.hash(f)
    data = json.loads(hasher.cache_file.read_text())
    assert len(data["entries"]) == 3


@posix_only
def test_unwritable_cache_dir_degrades_to_no_cache(tmp_path: Path) -> None:
    blocker = tmp_path / "blocker"
    blocker.write_text("i am a file, not a directory")
    model = _dir_model(tmp_path)
    result = CachedHasher(blocker / "cache").hash(model)  # mkdir fails -> swallowed
    assert not result.from_cache
    assert result.digest == hash_artifact(model)
