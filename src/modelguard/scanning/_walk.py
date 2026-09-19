"""Shared safe file-walking helper for scanners.

Unlike ``modelguard.hashing.digest``, which fails closed and raises
``UnsafePathError`` on any symlink or out-of-root path -- hashing is
the security-critical identity computation and must never silently
proceed on unsafe input -- scanning is best-effort. A symlink or an
out-of-root path is skipped and reported as a LOW-severity ``Finding``
so the rest of the artifact still gets scanned, rather than the whole
scan aborting over one unsafe entry. Symlinks are still never
followed: this module only changes what happens when one is found
(skip-and-report instead of raise), not whether it is followed.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from modelguard.scanning.models import Confidence, Finding, Severity


@dataclass(frozen=True, slots=True)
class ScannableFile:
    """One real, non-symlink file a scanner may safely open and read."""

    absolute_path: Path
    relative_path: str  # POSIX-style; for a single-file artifact this is just its name


def _skip_finding(scanner_name: str, path: str, reason: str) -> Finding:
    return Finding(
        scanner=scanner_name,
        category="scan_skipped",
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        component=path,
        message=f"Skipped during scan: {reason}.",
        remediation=(
            "Symlinks are never followed during scanning. If this entry is meant to be "
            "part of the artifact, replace it with a real file or directory."
        ),
    )


def iter_scannable_files(root: Path, scanner_name: str) -> Iterator[ScannableFile | Finding]:
    """Walk ``root`` (a file or a directory) without following symlinks.

    Yields a ``ScannableFile`` for every real file a scanner may safely
    read, and a LOW-severity ``Finding`` for every symlink or
    out-of-root entry encountered instead -- callers should route
    ``Finding`` items straight into their own results and treat
    everything else as scannable.
    """
    if root.is_symlink():
        yield _skip_finding(scanner_name, str(root), "artifact root is a symlink")
        return

    if root.is_file():
        yield ScannableFile(absolute_path=root, relative_path=root.name)
        return

    if not root.is_dir():
        return

    resolved_root = root.resolve()

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current_dir = Path(dirpath)

        for dname in dirnames:
            d = current_dir / dname
            if d.is_symlink():
                yield _skip_finding(scanner_name, str(d), "symlinked directory")

        for fname in filenames:
            file_path = current_dir / fname

            if file_path.is_symlink():
                yield _skip_finding(scanner_name, str(file_path), "symlinked file")
                continue

            resolved = file_path.resolve()
            try:
                relative = resolved.relative_to(resolved_root)
            except ValueError:
                yield _skip_finding(scanner_name, str(file_path), "resolves outside artifact root")
                continue

            yield ScannableFile(absolute_path=file_path, relative_path=relative.as_posix())
