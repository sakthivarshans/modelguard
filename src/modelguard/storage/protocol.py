"""Content-addressed blob store interface.

A blob is identified only by its SHA-256 (64 lowercase hex characters).
Names, locations, and buckets are deployment details; the digest is the
identity, matching the "names are mutable, digests are not" principle.

Implementations MUST verify content against the digest on both write
and read, and MUST NOT leave partial or unverified data at the
destination of a failed ``get_to``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol


class BlobStore(Protocol):
    def exists(self, sha256: str) -> bool:
        """Whether a blob is present. Backend errors raise, never return False."""
        ...

    def put(self, sha256: str, source: Path) -> None:
        """Store the regular file ``source`` under ``sha256``.

        Raises ``ArtifactIntegrityError`` (storing nothing) if the
        file's bytes do not hash to ``sha256``. Symlinks are refused.
        """
        ...

    def get_to(self, sha256: str, dest: Path, *, max_bytes: int) -> None:
        """Download the blob to ``dest`` (which must not exist), verifying
        its SHA-256 and enforcing ``max_bytes`` while streaming."""
        ...
