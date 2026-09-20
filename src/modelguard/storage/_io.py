"""Shared, security-sensitive I/O helpers for blob stores."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import uuid
from collections.abc import Iterable
from pathlib import Path
from typing import BinaryIO

from modelguard.storage.errors import ArtifactIntegrityError, ArtifactStoreError

CHUNK_SIZE = 1024 * 1024
_SHA256_RE = re.compile(r"[0-9a-f]{64}")


def validate_sha256(value: str) -> str:
    """Accept only 64 lowercase hex characters.

    Blob identifiers become path segments and object keys, so anything
    else (``../``, uppercase look-alikes, whitespace) is rejected rather
    than normalized.
    """
    if not _SHA256_RE.fullmatch(value):
        raise ArtifactStoreError("A blob identifier must be exactly 64 lowercase hex characters.")
    return value


def open_regular_nofollow(path: Path) -> BinaryIO:
    """Open ``path`` for reading, refusing symlinks and non-regular files.

    Uses ``O_NOFOLLOW`` and an ``fstat`` on the opened descriptor, so a
    file swapped for a symlink after hashing cannot be read (and
    uploaded) instead.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ArtifactStoreError(f"Cannot open source file safely ({type(exc).__name__}).") from None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ArtifactStoreError("Source is not a regular file.")
    except BaseException:
        os.close(fd)
        raise
    return os.fdopen(fd, "rb")


class HashingReader:
    """Read-only file wrapper that hashes everything read through it.

    Deliberately exposes only ``read`` (no ``seek``/``tell``) so upload
    libraries treat it as a stream and read it exactly once, in order.
    """

    def __init__(self, raw: BinaryIO) -> None:
        self._raw = raw
        self._hash = hashlib.sha256()

    def read(self, size: int = -1) -> bytes:
        chunk = self._raw.read(size)
        self._hash.update(chunk)
        return chunk

    def hexdigest(self) -> str:
        return self._hash.hexdigest()


def write_verified(
    chunks: Iterable[bytes], dest: Path, *, expected_sha256: str, max_bytes: int
) -> None:
    """Stream ``chunks`` to ``dest`` only if they hash to ``expected_sha256``.

    Data goes to a private temp file beside ``dest`` (created 0600,
    ``O_EXCL``) and is renamed into place only after the digest and size
    limit check out. On any failure the temp file is removed, so a
    failed or tampered download never leaves bytes at ``dest``.
    """
    if dest.exists() or dest.is_symlink():
        raise ArtifactStoreError("Destination already exists; refusing to overwrite it.")
    tmp = dest.with_name(f".{dest.name}.{uuid.uuid4().hex}.part")
    digest = hashlib.sha256()
    written = 0
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as out:
            for chunk in chunks:
                written += len(chunk)
                if written > max_bytes:
                    raise ArtifactIntegrityError(
                        f"Blob exceeds the size limit of {max_bytes} bytes; download aborted."
                    )
                digest.update(chunk)
                out.write(chunk)
        if digest.hexdigest() != expected_sha256:
            raise ArtifactIntegrityError(
                "Downloaded bytes do not match the expected SHA-256; the stored blob was "
                "modified or corrupted. Nothing was written."
            )
        os.replace(tmp, dest)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
