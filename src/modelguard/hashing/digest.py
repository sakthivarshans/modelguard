"""Deterministic artifact hashing.

This module implements the digest rules described in the ModelGuard
architecture document (section "Deterministic Artifact Digests"). These
rules are the foundation of every trust decision ModelGuard makes, so
they are documented explicitly here rather than left implicit in code.

Hashing rules (Phase 1, single filesystem root):

1. Algorithm: SHA-256, applied per-file and to the canonical manifest.
2. Files are enumerated with ``os.walk`` and sorted lexicographically by
   their POSIX-style relative path, so enumeration order never depends
   on the filesystem or operating system.
3. Paths are normalized to forward-slash, artifact-root-relative paths.
   No absolute paths, drive letters, or machine-specific segments are
   ever hashed.
4. Symlinks are rejected. ModelGuard does not follow or hash symlinks
   in Phase 1: a symlink could point outside the artifact root (path
   traversal) or be swapped after inspection (a TOCTOU-style attack).
   Fail closed: raise ``UnsafePathError`` rather than silently skip.
5. Hidden files (dotfiles) are included. A model artifact's trust
   should not depend on files a scanner might silently ignore.
6. File content only is hashed. Filesystem timestamps and permission
   bits are intentionally excluded from the digest, since they are not
   reproducible across clones, container layers, or CI checkouts.
7. Empty directories are not represented (SHA-256 has nothing to hash
   for them); only files contribute to the digest.
8. Large files are streamed in fixed-size chunks; the whole file is
   never loaded into memory at once.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

from modelguard.exceptions import (
    ArtifactNotFoundError,
    EmptyArtifactError,
    UnsafePathError,
)

_CHUNK_SIZE = 1024 * 1024  # 1 MiB streaming chunks
_DIGEST_ALGORITHM = "sha256"


@dataclass(frozen=True, slots=True)
class FileDigest:
    """The digest of a single file within an artifact."""

    path: str  # POSIX-style, artifact-root-relative
    sha256: str
    size: int


@dataclass(frozen=True, slots=True)
class ArtifactDigest:
    """The result of hashing a whole artifact (file or directory).

    ``digest`` is the artifact's immutable identity: two artifacts with
    the same ``digest`` are byte-for-byte identical under these hashing
    rules. ``files`` is empty for a single-file artifact.
    """

    algorithm: str
    artifact_type: str  # "file" or "directory"
    digest: str
    files: tuple[FileDigest, ...]

    @property
    def uri_fragment(self) -> str:
        """The ``@sha256:...`` fragment used in immutable model URIs."""
        return f"@{self.algorithm}:{self.digest}"


def _hash_file_bytes(path: Path) -> tuple[str, int]:
    hasher = hashlib.sha256()
    size = 0
    with path.open("rb") as fh:
        while chunk := fh.read(_CHUNK_SIZE):
            hasher.update(chunk)
            size += len(chunk)
    return hasher.hexdigest(), size


def _canonical_manifest_bytes(files: list[FileDigest]) -> bytes:
    """Build the canonical JSON representation that gets hashed to
    produce a directory artifact's digest.

    Canonical form: a JSON object with sorted keys, no insignificant
    whitespace, and files sorted by path — so the same file set always
    serializes to the same bytes regardless of dict/set ordering.
    """
    payload = {
        "algorithm": _DIGEST_ALGORITHM,
        "files": [
            {"path": f.path, "sha256": f.sha256, "size": f.size}
            for f in sorted(files, key=lambda f: f.path)
        ],
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def canonical_manifest_bytes(files: list[FileDigest] | tuple[FileDigest, ...]) -> bytes:
    """The canonical bytes whose SHA-256 is a directory artifact's digest.

    Public so the object-store transfer code can store and re-verify the
    exact bytes the digest was computed over.
    """
    return _canonical_manifest_bytes(list(files))


def artifact_digest_from_files(
    artifact_type: str, files: list[FileDigest] | tuple[FileDigest, ...]
) -> ArtifactDigest:
    """Derive an ``ArtifactDigest`` from already-computed per-file digests.

    This is the single place the artifact-level digest rules live, so
    ``hash_directory`` and anything that needs to *re-derive* a digest
    from stored per-file digests (e.g. the verification cache's
    consistency check) cannot drift apart.

    * ``"file"``: exactly one file; the artifact digest is that file's
      SHA-256.
    * ``"directory"``: the SHA-256 of the canonical manifest of all
      files (see ``_canonical_manifest_bytes``).
    """
    if artifact_type == "file":
        if len(files) != 1:
            raise ValueError("a file artifact has exactly one file digest")
        return ArtifactDigest(
            algorithm=_DIGEST_ALGORITHM,
            artifact_type="file",
            digest=files[0].sha256,
            files=tuple(files),
        )
    if artifact_type != "directory":
        raise ValueError(f"unknown artifact_type: {artifact_type!r}")
    manifest_bytes = _canonical_manifest_bytes(list(files))
    return ArtifactDigest(
        algorithm=_DIGEST_ALGORITHM,
        artifact_type="directory",
        digest=hashlib.sha256(manifest_bytes).hexdigest(),
        files=tuple(sorted(files, key=lambda f: f.path)),
    )


def hash_file(path: Path) -> ArtifactDigest:
    """Hash a single file artifact."""
    if not path.is_file():
        raise ArtifactNotFoundError(str(path))
    if path.is_symlink():
        raise UnsafePathError(str(path), "artifact root is a symlink")

    digest, size = _hash_file_bytes(path)
    file_digest = FileDigest(path=path.name, sha256=digest, size=size)
    return artifact_digest_from_files("file", [file_digest])


def hash_directory(root: Path) -> ArtifactDigest:
    """Hash a directory artifact using the canonical manifest rules
    documented at the top of this module.

    Raises:
        ArtifactNotFoundError: ``root`` does not exist or is not a directory.
        UnsafePathError: a symlink or an out-of-root path was encountered.
        EmptyArtifactError: the directory contains no hashable files.
    """
    if not root.is_dir():
        raise ArtifactNotFoundError(str(root))

    resolved_root = root.resolve()
    file_digests: list[FileDigest] = []

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # Reject symlinked subdirectories explicitly rather than letting
        # os.walk silently skip them (followlinks=False just means "don't
        # descend"; the entry would otherwise be silently dropped).
        current_dir = Path(dirpath)
        for dname in dirnames:
            d = current_dir / dname
            if d.is_symlink():
                raise UnsafePathError(str(d), "symlinked directory")

        for fname in filenames:
            file_path = current_dir / fname
            if file_path.is_symlink():
                raise UnsafePathError(str(file_path), "symlinked file")

            resolved = file_path.resolve()
            try:
                relative = resolved.relative_to(resolved_root)
            except ValueError as exc:
                raise UnsafePathError(
                    str(file_path), "resolves outside artifact root"
                ) from exc

            posix_path = relative.as_posix()
            digest, size = _hash_file_bytes(file_path)
            file_digests.append(FileDigest(path=posix_path, sha256=digest, size=size))

    if not file_digests:
        raise EmptyArtifactError(str(root))

    return artifact_digest_from_files("directory", file_digests)


def hash_artifact(path: Path) -> ArtifactDigest:
    """Hash a file or directory artifact, dispatching on its type.

    This is the single public entry point most callers should use.
    """
    if not path.exists():
        raise ArtifactNotFoundError(str(path))
    if path.is_symlink():
        raise UnsafePathError(str(path), "artifact root is a symlink")
    if path.is_dir():
        return hash_directory(path)
    return hash_file(path)
