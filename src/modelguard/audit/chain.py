"""A generic, tamper-evident, append-only log.

Both the audit log and the provenance store need the same property:
records that, once written, cannot be silently altered or deleted
without detection. Rather than implement that twice, this module
provides one primitive both build on.

Design: JSON Lines file where each line is a record plus the SHA-256
hash of the *previous* line's record bytes (`prev_hash`), forming a
hash chain -- the same idea used by Sigstore/in-toto-adjacent
transparency logs and blockchains, without the distributed-consensus
machinery ModelGuard's docs explicitly say not to add by default.

This detects:
  - A record being edited in place (its bytes change -> every
    subsequent prev_hash it, transitively, no longer matches).
  - A record being deleted from the middle (the chain breaks: the
    following record's prev_hash won't match its new predecessor).
  - Records being reordered.

This does NOT detect:
  - Truncation of the *tail* of the file (deleting the last N
    records) -- nothing downstream exists to notice. A future
    Merkle-checkpoint or external timestamping adapter closes this
    gap; it is out of scope here and documented as a limitation.
  - A privileged local attacker with write access simply replacing
    the whole file with a self-consistent forged chain. This is a
    tamper-evidence mechanism for accidental or partial corruption
    and for detecting edits by a less-privileged actor, not a
    defense against a fully compromised host.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_GENESIS_HASH = "0" * 64


@dataclass(frozen=True, slots=True)
class ChainEntry:
    """One record in the chain, as read back from disk."""

    index: int
    record: dict[str, Any]
    record_hash: str
    prev_hash: str


class ChainIntegrityError(Exception):
    """The chain has been tampered with, reordered, or truncated in the middle."""

    def __init__(self, index: int, reason: str) -> None:
        self.index = index
        self.reason = reason
        super().__init__(f"Hash chain broken at entry {index}: {reason}")


def _record_bytes(record: dict[str, Any]) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")


def append_entry(log_path: Path, record: dict[str, Any]) -> ChainEntry:
    """Append ``record`` to the chain at ``log_path``, computing its
    hash-chain linkage. Creates the file (and parent directories) if
    it does not exist.
    """
    log_path.parent.mkdir(parents=True, exist_ok=True)

    prev_hash = _GENESIS_HASH
    index = 0
    if log_path.exists() and log_path.stat().st_size > 0:
        last = _read_last_entry(log_path)
        prev_hash = last.record_hash
        index = last.index + 1

    record_hash = hashlib.sha256(_record_bytes(record) + prev_hash.encode("utf-8")).hexdigest()
    line = {
        "index": index,
        "prev_hash": prev_hash,
        "record_hash": record_hash,
        "record": record,
    }

    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(line, sort_keys=True, separators=(",", ":")) + "\n")

    return ChainEntry(index=index, record=record, record_hash=record_hash, prev_hash=prev_hash)


def _read_last_entry(log_path: Path) -> ChainEntry:
    last_line: str | None = None
    with log_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                last_line = line
    if last_line is None:
        raise ChainIntegrityError(0, "log file exists but contains no entries")
    data = json.loads(last_line)
    return ChainEntry(
        index=data["index"],
        record=data["record"],
        record_hash=data["record_hash"],
        prev_hash=data["prev_hash"],
    )


def read_all_entries(log_path: Path) -> list[ChainEntry]:
    """Read every entry in file order without verifying the chain."""
    if not log_path.exists():
        return []
    entries: list[ChainEntry] = []
    with log_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            data = json.loads(line)
            entries.append(
                ChainEntry(
                    index=data["index"],
                    record=data["record"],
                    record_hash=data["record_hash"],
                    prev_hash=data["prev_hash"],
                )
            )
    return entries


def verify_chain(log_path: Path) -> None:
    """Recompute and check every link in the chain.

    Raises ``ChainIntegrityError`` at the first broken link. Fails
    closed: callers that need to trust a log's contents must call this
    before relying on ``read_all_entries``.
    """
    expected_prev = _GENESIS_HASH
    for entry in read_all_entries(log_path):
        if entry.prev_hash != expected_prev:
            raise ChainIntegrityError(
                entry.index, "prev_hash does not match the preceding entry's record_hash"
            )
        recomputed = hashlib.sha256(
            _record_bytes(entry.record) + entry.prev_hash.encode("utf-8")
        ).hexdigest()
        if recomputed != entry.record_hash:
            raise ChainIntegrityError(entry.index, "record_hash does not match record contents")
        expected_prev = entry.record_hash
