"""Local, directory-backed content-addressed blob store.

Layout: ``<root>/blobs/sha256/<first two hex>/<hex>``. Works with no
external service, and serves as the reference implementation for the
``BlobStore`` contract that the S3 adapter must also satisfy.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO

from modelguard.storage._io import (
    CHUNK_SIZE,
    HashingReader,
    open_regular_nofollow,
    validate_sha256,
    write_verified,
)
from modelguard.storage.errors import (
    ArtifactIntegrityError,
    ArtifactNotFoundError,
    ArtifactStoreError,
)


class LocalBlobStore:
    def __init__(self, root: Path) -> None:
        self._root = Path(root)

    def _blob_path(self, sha256: str) -> Path:
        validate_sha256(sha256)
        return self._root / "blobs" / "sha256" / sha256[:2] / sha256

    def exists(self, sha256: str) -> bool:
        path = self._blob_path(sha256)
        return path.is_file() and not path.is_symlink()

    def put(self, sha256: str, source: Path) -> None:
        final = self._blob_path(sha256)
        final.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = final.with_name(f".{sha256}.{os.getpid()}.part")
        try:
            with open_regular_nofollow(source) as raw:
                reader = HashingReader(raw)
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as out:
                    while chunk := reader.read(CHUNK_SIZE):
                        out.write(chunk)
                if reader.hexdigest() != sha256:
                    raise ArtifactIntegrityError(
                        "The source file does not hash to the claimed SHA-256 (it may have "
                        "changed after hashing); nothing was stored."
                    )
            os.replace(tmp, final)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise

    def get_to(self, sha256: str, dest: Path, *, max_bytes: int) -> None:
        path = self._blob_path(sha256)
        try:
            with open_regular_nofollow(path) as raw:
                write_verified(
                    _chunks(raw), dest, expected_sha256=sha256, max_bytes=max_bytes
                )
        except ArtifactStoreError:
            if not path.exists() and not path.is_symlink():
                raise ArtifactNotFoundError("Blob not found in the local store.") from None
            raise


def _chunks(raw: BinaryIO) -> Iterator[bytes]:
    while chunk := raw.read(CHUNK_SIZE):
        yield chunk
