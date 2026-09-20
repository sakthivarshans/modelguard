"""Upload and download whole artifacts through a ``BlobStore``.

Model: every file is a blob keyed by its SHA-256. A *directory*
artifact additionally stores its canonical manifest (the exact bytes
whose SHA-256 is the artifact digest) as a blob under the artifact
digest, so knowing only the artifact digest is enough to fetch, verify
and rebuild the whole tree. A single-file artifact is just its blob.

Download guarantees:

* Every blob is verified against its digest while streaming; the
  manifest is verified against the artifact digest *first*.
* The manifest is then validated anyway, because the digest proves who
  signed those bytes, not that they are safe to act on: paths that are
  absolute, contain ``..``, backslashes, control characters, empty or
  ``.`` segments, or that collide (duplicates, file-vs-directory) are
  refused, as are non-canonical manifests, wrong sizes, and anything
  over the file-count or total-size limits.
* The tree is built in a private staging directory next to the
  destination and renamed into place atomically. On any failure the
  staging directory is removed; nothing pre-existing at the destination
  is ever touched (the destination must not exist).
* No symlinks are ever created.

Limitations: case-insensitive filesystems can merge paths that differ
only by case; downloaded files are created ``0600`` and directories
``0700`` (loosen deliberately if another user must read them).
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unicodedata
import uuid
from pathlib import Path
from typing import Any

from modelguard.hashing.digest import (
    ArtifactDigest,
    FileDigest,
    artifact_digest_from_files,
    canonical_manifest_bytes,
    hash_artifact,
)
from modelguard.storage._io import validate_sha256
from modelguard.storage.errors import ArtifactIntegrityError, ArtifactStoreError
from modelguard.storage.protocol import BlobStore

DEFAULT_MAX_TOTAL_BYTES = 256 * 1024**3
DEFAULT_MAX_FILES = 100_000
MAX_MANIFEST_BYTES = 64 * 1024**2
_MAX_SEGMENT = 255
_MAX_PATH = 4096


def upload_artifact(store: BlobStore, path: Path) -> ArtifactDigest:
    """Hash ``path`` (refusing symlinks and other unsafe input) and upload it.

    Returns the artifact digest to record in your manifest/registry.
    Blobs already present are not re-uploaded. Each upload re-verifies
    the bytes it sends, so a file modified after hashing is refused
    rather than stored under the wrong identity.
    """
    digest = hash_artifact(path)
    if digest.artifact_type == "file":
        _put_if_absent(store, digest.files[0].sha256, path)
        return digest

    for entry in digest.files:
        _put_if_absent(store, entry.sha256, path / entry.path)

    with tempfile.TemporaryDirectory() as tmp:
        manifest_file = Path(tmp) / "manifest.json"
        manifest_file.write_bytes(canonical_manifest_bytes(digest.files))
        _put_if_absent(store, digest.digest, manifest_file)
    return digest


def _put_if_absent(store: BlobStore, sha256: str, source: Path) -> None:
    if not store.exists(sha256):
        store.put(sha256, source)


def download_artifact(
    store: BlobStore,
    artifact_digest: str,
    artifact_type: str,
    dest: Path,
    *,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_files: int = DEFAULT_MAX_FILES,
    verify_after: bool = True,
) -> None:
    """Fetch, verify and materialize an artifact at ``dest`` (must not exist).

    ``artifact_digest`` is ``"sha256:<hex>"`` and should come from a
    source you trust (a verified signature or registry record), never
    from the store itself. ``artifact_type`` is ``"file"`` or
    ``"directory"``. With ``verify_after`` (default) the finished
    artifact is re-hashed from disk as a final check.
    """
    algorithm, _, expected = artifact_digest.partition(":")
    if algorithm != "sha256":
        raise ArtifactStoreError("Only sha256 artifact digests are supported.")
    validate_sha256(expected)
    if artifact_type not in {"file", "directory"}:
        raise ArtifactStoreError("artifact_type must be 'file' or 'directory'.")
    if dest.exists() or dest.is_symlink():
        raise ArtifactStoreError("Destination already exists; refusing to overwrite it.")
    dest.parent.mkdir(parents=True, exist_ok=True)

    if artifact_type == "file":
        store.get_to(expected, dest, max_bytes=max_total_bytes)
        return

    files = _fetch_manifest(store, expected, max_files, max_total_bytes)

    staging = dest.parent / f".mg-stage-{uuid.uuid4().hex}"
    staging.mkdir(mode=0o700)
    try:
        staging_root = staging.resolve()
        for entry in files:
            target = staging / entry.path
            if not target.resolve().is_relative_to(staging_root):  # defense in depth
                raise ArtifactIntegrityError("A manifest path escaped the staging directory.")
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            store.get_to(entry.sha256, target, max_bytes=entry.size)
            if target.stat().st_size != entry.size:
                raise ArtifactIntegrityError(
                    f"{entry.path!r} has a different size than the manifest declares."
                )
        os.rename(staging, dest)
    except BaseException as exc:
        shutil.rmtree(staging, ignore_errors=True)
        if isinstance(exc, OSError) and not isinstance(exc, ArtifactStoreError):
            raise ArtifactStoreError(
                f"Could not materialize the artifact ({type(exc).__name__})."
            ) from None
        raise

    if verify_after:
        rebuilt = hash_artifact(dest)
        if rebuilt.digest != expected:
            shutil.rmtree(dest, ignore_errors=True)
            raise ArtifactIntegrityError(
                "The rebuilt artifact does not hash to the expected digest; it was removed."
            )


def _fetch_manifest(
    store: BlobStore, expected: str, max_files: int, max_total_bytes: int
) -> list[FileDigest]:
    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp) / "manifest.json"
        store.get_to(expected, target, max_bytes=MAX_MANIFEST_BYTES)  # hash-verified
        raw = target.read_bytes()
    files = _parse_manifest(raw, max_files, max_total_bytes)

    # The hash matched, but the bytes must also be the canonical form so
    # that what we act on is exactly what `hash_artifact` would produce.
    rederived = artifact_digest_from_files("directory", files)
    if rederived.digest != expected or canonical_manifest_bytes(files) != raw:
        raise ArtifactIntegrityError(
            "The stored manifest is not in canonical form for this digest; refusing it."
        )
    return files


def _parse_manifest(raw: bytes, max_files: int, max_total_bytes: int) -> list[FileDigest]:
    try:
        doc = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise ArtifactIntegrityError("The stored manifest is not valid JSON.") from None
    if not isinstance(doc, dict) or set(doc) != {"algorithm", "files"} or doc["algorithm"] != "sha256":
        raise ArtifactIntegrityError("The stored manifest has an unexpected structure.")
    entries = doc["files"]
    if not isinstance(entries, list) or not entries:
        raise ArtifactIntegrityError("The stored manifest lists no files.")
    if len(entries) > max_files:
        raise ArtifactIntegrityError(f"The manifest lists more than {max_files} files.")

    files: list[FileDigest] = []
    seen: set[str] = set()
    total = 0
    for item in entries:
        files.append(_parse_entry(item))
        entry = files[-1]
        if entry.path in seen:
            raise ArtifactIntegrityError(f"Duplicate path in manifest: {entry.path!r}.")
        seen.add(entry.path)
        total += entry.size
        if total > max_total_bytes:
            raise ArtifactIntegrityError("The artifact exceeds the total size limit.")

    for path in seen:  # a path must not be both a file and a directory
        if any(other.startswith(path + "/") for other in seen):
            raise ArtifactIntegrityError(f"Manifest path {path!r} is both a file and a directory.")
    return files


def _parse_entry(item: Any) -> FileDigest:
    if not isinstance(item, dict) or set(item) != {"path", "sha256", "size"}:
        raise ArtifactIntegrityError("A manifest entry has an unexpected structure.")
    path, sha, size = item["path"], item["sha256"], item["size"]
    if not isinstance(path, str) or not isinstance(sha, str):
        raise ArtifactIntegrityError("A manifest entry has non-string fields.")
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise ArtifactIntegrityError("A manifest entry has an invalid size.")
    _check_relative_path(path)
    try:
        validate_sha256(sha)
    except ArtifactStoreError:
        raise ArtifactIntegrityError("A manifest entry has an invalid SHA-256.") from None
    return FileDigest(path, sha, size)


def _check_relative_path(path: str) -> None:
    problem: str | None = None
    if not path or len(path) > _MAX_PATH:
        problem = "empty or too long"
    elif path.startswith("/") or "\\" in path:
        problem = "absolute or contains a backslash"
    elif any(unicodedata.category(c) == "Cc" for c in path):
        problem = "contains control characters"
    else:
        for segment in path.split("/"):
            if segment in {"", ".", ".."} or len(segment) > _MAX_SEGMENT:
                problem = "has an empty, '.', '..' or over-long segment"
                break
    if problem:
        raise ArtifactIntegrityError(f"Unsafe path in manifest ({problem}): {path[:80]!r}.")
