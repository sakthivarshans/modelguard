"""Local, file-backed registry implementation.

Storage layout under the registry root:

    records/<model_id>/<version>.json   -- one RegistryRecord each
    digest_index.json                   -- {digest: {model_id, version}}
    revocations.log.jsonl               -- hash-chained revoke/unrevoke events

This is the adapter used when no PostgreSQL registry service is
configured, matching the project rule that the framework must work
locally with no external services. A future PostgreSQL-backed registry
implements the same ``Registry`` protocol.
"""

from __future__ import annotations

import json
from pathlib import Path

from modelguard.audit.chain import append_entry, read_all_entries
from modelguard.registry.errors import DuplicateRegistrationError
from modelguard.registry.identifiers import validate_identifier
from modelguard.registry.models import RegistryRecord, RevocationRecord


class LocalRegistry:
    """File-backed ``Registry`` implementation rooted at ``root``."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self._records_dir = root / "records"
        self._digest_index_path = root / "digest_index.json"
        self._revocation_log_path = root / "revocations.log.jsonl"

    # -- registration ------------------------------------------------

    def register(self, record: RegistryRecord) -> RegistryRecord:
        version_path = self._version_path(record.model_id, record.version)
        if version_path.exists():
            raise DuplicateRegistrationError(record.model_id, record.version)

        version_path.parent.mkdir(parents=True, exist_ok=True)
        version_path.write_text(record.model_dump_json(indent=2))

        # First registration wins. Registering identical bytes under a
        # second name must not change what the digest resolves to,
        # otherwise a later registrant could repoint an immutable
        # identity at their own name.
        index = self._read_digest_index()
        if record.artifact_digest not in index:
            index[record.artifact_digest] = {"model_id": record.model_id, "version": record.version}
            self._write_digest_index(index)

        return record

    def get(self, model_id: str, version: str) -> RegistryRecord | None:
        path = self._version_path(model_id, version)
        if not path.exists():
            return None
        return RegistryRecord.model_validate(json.loads(path.read_text()))

    def get_by_digest(self, artifact_digest: str) -> RegistryRecord | None:
        index = self._read_digest_index()
        entry = index.get(artifact_digest)
        if entry is None:
            return None
        return self.get(entry["model_id"], entry["version"])

    def list_versions(self, model_id: str) -> list[str]:
        model_dir = self._records_dir / _safe_segment(model_id)
        if not model_dir.exists():
            return []
        return sorted(p.stem for p in model_dir.glob("*.json"))

    # -- revocation ----------------------------------------------------

    def revoke(self, record: RevocationRecord) -> RevocationRecord:
        validate_identifier(record.model_id, field="model_id")
        validate_identifier(record.version, field="version")
        append_entry(
            self._revocation_log_path,
            {"action": "revoke", **record.model_dump()},
        )
        return record

    def unrevoke(self, model_id: str, version: str, actor: str, reason: str) -> None:
        validate_identifier(model_id, field="model_id")
        validate_identifier(version, field="version")
        append_entry(
            self._revocation_log_path,
            {
                "action": "unrevoke",
                "model_id": model_id,
                "version": version,
                "revoked_by": actor,
                "reason": reason,
            },
        )

    def is_revoked(self, model_id: str, version: str) -> RevocationRecord | None:
        """Return the active ``RevocationRecord`` if this version is
        currently revoked, else ``None``.

        Determined by replaying the revocation log for this
        model_id/version and taking the latest action -- a subsequent
        ``unrevoke`` clears an earlier ``revoke``, but the history of
        both remains in the log for audit purposes.
        """
        validate_identifier(model_id, field="model_id")
        validate_identifier(version, field="version")
        latest_revoke: RevocationRecord | None = None
        for entry in read_all_entries(self._revocation_log_path):
            r = entry.record
            if r["model_id"] != model_id or r["version"] != version:
                continue
            if r["action"] == "revoke":
                latest_revoke = RevocationRecord(
                    model_id=r["model_id"],
                    version=r["version"],
                    revoked_by=r["revoked_by"],
                    reason=r["reason"],
                    revoked_at=r["revoked_at"],
                )
            elif r["action"] == "unrevoke":
                latest_revoke = None
        return latest_revoke

    # -- internals -------------------------------------------------------

    def _version_path(self, model_id: str, version: str) -> Path:
        return self._records_dir / _safe_segment(model_id) / f"{_safe_segment(version)}.json"

    def _read_digest_index(self) -> dict[str, dict[str, str]]:
        if not self._digest_index_path.exists():
            return {}
        data: dict[str, dict[str, str]] = json.loads(self._digest_index_path.read_text())
        return data

    def _write_digest_index(self, index: dict[str, dict[str, str]]) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self._digest_index_path.write_text(json.dumps(index, indent=2, sort_keys=True))


def _safe_segment(value: str) -> str:
    """Validate a model_id/version before using it as a path segment.

    Delegates to the shared registry identifier rules (rejecting, never
    silently stripping, unsafe input), so every backend agrees on what
    a valid identifier is.
    """
    return validate_identifier(value)
