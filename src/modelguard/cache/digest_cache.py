"""Opt-in local cache for artifact digests.

WHAT IS CACHED -- AND WHAT IS NOT
---------------------------------
Only the *digest computation* is cached: a pure function of the
artifact's file bytes. Everything that can change independently of
those bytes is recomputed on every call and never cached:

* signature verification,
* ML-BOM binding,
* trusted-signer checks,
* revocation state,
* policy evaluation.

That split is what makes "a cached result must never override a newly
revoked signer or model" true by construction rather than by careful
invalidation: the cache has no opinion about revocation to go stale.

HOW A HIT IS DECIDED
--------------------
A hit means "the files look unchanged since ModelGuard last hashed
them", judged from filesystem metadata alone, so the artifact is not
re-read. For every file we record ``(relative path, size, mtime_ns,
ctime_ns, inode, device)``. ``ctime`` is the important one: on POSIX an
unprivileged process cannot set it, and any content change advances it,
so restoring ``mtime`` with ``os.utime`` does not hide an edit.

Two safeguards borrowed from how git's index handles the same problem:

1. **Racy timestamps.** An entry is only stored if every file's
   ``max(mtime, ctime)`` is at least ``RACY_MARGIN_NS`` older than the
   moment of storing. Otherwise an edit landing in the same timestamp
   tick as the hash could be invisible later.
2. **Stat-hash-stat.** The fingerprint is captured before hashing and
   again after; if it changed during hashing, nothing is stored.

TRUST ASSUMPTIONS (read these before enabling the cache)
--------------------------------------------------------
* The filesystem reports honest metadata. An attacker with root, raw
  block-device access, or the ability to set the system clock defeats
  this. Writes through a shared ``mmap`` may not update ``mtime`` or
  ``ctime`` promptly on some systems. Network/FUSE filesystems with
  attribute caching, and Windows (where ``st_ctime`` is *creation*
  time), are unsupported: the cache is bypassed entirely off POSIX and
  for any file reporting inode 0.
* The cache file is as trusted as the verifying process. We refuse a
  cache file that is a symlink, not owned by the current user, or
  group/world-writable, and we treat any corrupt or inconsistent
  entry as a miss -- but an attacker who can write the cache as the
  same user can forge an entry. Keep the cache directory somewhere the
  artifact's supplier cannot write.
* Anything uncertain is a miss. A miss costs time, never correctness.
"""

from __future__ import annotations

import json
import logging
import os
import stat
import time
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from modelguard.hashing.digest import (
    ArtifactDigest,
    FileDigest,
    artifact_digest_from_files,
    hash_artifact,
)

logger = logging.getLogger("modelguard.cache")

CACHE_SCHEMA_VERSION = 1
CACHE_FILENAME = f"digest-cache-v{CACHE_SCHEMA_VERSION}.json"
RACY_MARGIN_NS = 2_000_000_000  # 2 seconds: covers coarse (1s/2s) mtime granularity
MAX_CACHE_FILE_BYTES = 16 * 1024 * 1024
MAX_ENTRIES = 128

_SHA256_PATTERN = r"^[0-9a-f]{64}$"


@dataclass(frozen=True, slots=True)
class CachedHashResult:
    """A digest plus whether it came from the cache (for transparency
    in verification results and audit records)."""

    digest: ArtifactDigest
    from_cache: bool


class _StatModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    relpath: str
    size: int = Field(ge=0)
    mtime_ns: int
    ctime_ns: int
    ino: int
    dev: int


class _FileDigestModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str
    sha256: str = Field(pattern=_SHA256_PATTERN)
    size: int = Field(ge=0)


class _Entry(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    artifact_type: str
    files: list[_FileDigestModel]
    stats: list[_StatModel]
    recorded_at_ns: int


class _CacheFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int
    entries: dict[str, _Entry] = Field(default_factory=dict)


def _capture_fingerprint(path: Path) -> tuple[str, list[_StatModel]] | None:
    """Return ``(artifact_type, per-file stats)`` or ``None`` if the
    artifact cannot be cached safely.

    Applies the same safety rules as hashing -- never follow a symlink,
    only regular files -- but returns ``None`` (uncacheable) instead of
    raising, so the real hashing code path produces the authoritative
    error for anything unusual.
    """
    if os.name != "posix":
        return None
    try:
        root_stat = os.lstat(path)
        if stat.S_ISLNK(root_stat.st_mode):
            return None

        if stat.S_ISREG(root_stat.st_mode):
            single = _stat_model(path.name, root_stat)
            return ("file", [single]) if single.ino != 0 else None

        if not stat.S_ISDIR(root_stat.st_mode):
            return None

        dir_stats: list[_StatModel] = []
        for dirpath, dirnames, filenames in os.walk(path, followlinks=False):
            for dname in dirnames:
                if stat.S_ISLNK(os.lstat(os.path.join(dirpath, dname)).st_mode):
                    return None
            for fname in filenames:
                full = os.path.join(dirpath, fname)
                st = os.lstat(full)
                if not stat.S_ISREG(st.st_mode) or st.st_ino == 0:
                    return None
                rel = os.path.relpath(full, path).replace(os.sep, "/")
                dir_stats.append(_stat_model(rel, st))
        if not dir_stats:
            return None
        dir_stats.sort(key=lambda s: s.relpath)
        return "directory", dir_stats
    except OSError:
        return None


def _stat_model(relpath: str, st: os.stat_result) -> _StatModel:
    return _StatModel(
        relpath=relpath,
        size=st.st_size,
        mtime_ns=st.st_mtime_ns,
        ctime_ns=st.st_ctime_ns,
        ino=st.st_ino,
        dev=st.st_dev,
    )


def _all_older_than_margin(stats: list[_StatModel], now_ns: int) -> bool:
    cutoff = now_ns - RACY_MARGIN_NS
    return all(max(s.mtime_ns, s.ctime_ns) <= cutoff for s in stats)


def _entry_is_consistent(entry: _Entry, artifact_type: str, stats: list[_StatModel]) -> bool:
    """Cheap self-consistency check on a cached entry.

    Detects corruption and sloppy edits (mismatched file lists, or a
    stored artifact digest that no longer derives from the stored
    per-file digests). It is NOT a defense against a same-user attacker
    who forges a fully consistent entry -- see the module docstring.
    """
    if entry.artifact_type != artifact_type:
        return False
    return [(f.path, f.size) for f in entry.files] == [(s.relpath, s.size) for s in stats]


class CachedHasher:
    """Hash artifacts, reusing previous digests for unchanged files.

    Construct with a cache directory; ``hash()`` is a drop-in for
    ``hash_artifact`` that additionally reports whether the cache was
    used. Instances hold no mutable state, so one instance can be
    shared between threads (the on-disk file is last-writer-wins).
    """

    def __init__(self, cache_dir: Path) -> None:
        self._cache_dir = Path(cache_dir)

    @property
    def cache_file(self) -> Path:
        return self._cache_dir / CACHE_FILENAME

    def hash(self, path: Path) -> CachedHashResult:
        before = _capture_fingerprint(path)
        if before is None:
            return CachedHashResult(hash_artifact(path), from_cache=False)

        artifact_type, stats = before
        key = str(path.resolve())

        entry = self._load().entries.get(key)
        if entry is not None and entry.stats == stats and _entry_is_consistent(
            entry, artifact_type, stats
        ):
            try:
                digest = artifact_digest_from_files(
                    entry.artifact_type,
                    [FileDigest(f.path, f.sha256, f.size) for f in entry.files],
                )
            except ValueError:
                digest = None
            if digest is not None:
                return CachedHashResult(digest, from_cache=True)

        computed = hash_artifact(path)

        after = _capture_fingerprint(path)
        if after is None or after[1] != stats:
            logger.debug("artifact changed while hashing; not caching %s", key)
        elif not _all_older_than_margin(stats, time.time_ns()):
            logger.debug("artifact modified too recently to cache safely: %s", key)
        else:
            self._store(
                key,
                _Entry(
                    artifact_type=computed.artifact_type,
                    files=[
                        _FileDigestModel(path=f.path, sha256=f.sha256, size=f.size)
                        for f in computed.files
                    ],
                    stats=stats,
                    recorded_at_ns=time.time_ns(),
                ),
            )
        return CachedHashResult(computed, from_cache=False)

    # -- persistence -------------------------------------------------

    def _empty(self) -> _CacheFile:
        return _CacheFile(schema_version=CACHE_SCHEMA_VERSION)

    def _load(self) -> _CacheFile:
        path = self.cache_file
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            return self._empty()
        except OSError as exc:
            logger.warning("digest cache unreadable (%s); ignoring it", exc)
            return self._empty()

        if not stat.S_ISREG(st.st_mode):
            logger.warning("digest cache %s is not a regular file; ignoring it", path)
            return self._empty()
        if st.st_uid != os.getuid():
            logger.warning("digest cache %s is not owned by the current user; ignoring it", path)
            return self._empty()
        if st.st_mode & 0o022:
            logger.warning("digest cache %s is group/world-writable; ignoring it", path)
            return self._empty()
        if st.st_size > MAX_CACHE_FILE_BYTES:
            logger.warning("digest cache %s exceeds the size limit; ignoring it", path)
            return self._empty()

        try:
            loaded = _CacheFile.model_validate_json(path.read_bytes())
        except (OSError, ValidationError, ValueError, json.JSONDecodeError) as exc:
            logger.warning("digest cache %s is corrupt (%s); ignoring it", path, type(exc).__name__)
            return self._empty()
        if loaded.schema_version != CACHE_SCHEMA_VERSION:
            return self._empty()
        return loaded

    def _store(self, key: str, entry: _Entry) -> None:
        """Best-effort atomic write. Failure costs performance only, so
        it is logged and swallowed -- it never affects a verification
        outcome."""
        tmp_path = self._cache_dir / f".{CACHE_FILENAME}.{os.getpid()}.tmp"
        try:
            cache = self._load()
            cache.entries[key] = entry
            if len(cache.entries) > MAX_ENTRIES:
                oldest_first = sorted(cache.entries.items(), key=lambda kv: kv[1].recorded_at_ns)
                for old_key, _ in oldest_first[: len(cache.entries) - MAX_ENTRIES]:
                    del cache.entries[old_key]

            self._cache_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(fd, cache.model_dump_json().encode("utf-8"))
            finally:
                os.close(fd)
            os.replace(tmp_path, self.cache_file)
        except OSError as exc:
            logger.warning("could not write digest cache (%s); continuing without it", exc)
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
