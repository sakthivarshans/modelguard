"""Manifest data model.

A manifest is the canonical, signable description of one artifact: its
identity, its per-file digests, and whatever declared metadata the
caller supplies. The manifest schema is versioned independently of the
rest of ModelGuard so it can evolve without breaking signatures made
against an older schema version.
"""

from __future__ import annotations

import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

MANIFEST_SCHEMA_VERSION = "1"


class ManifestFileEntry(BaseModel):
    """One file's digest within a directory artifact's manifest."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str
    sha256: str
    size: int


class Manifest(BaseModel):
    """Canonical, signable manifest for a single model artifact.

    Only ``schema_version``, ``artifact_type``, ``algorithm`` and
    ``digest`` are guaranteed to be populated from actual measurement.
    Every other field is caller-declared metadata and MUST be treated
    as DECLARED evidence, not VERIFIED evidence, until independently
    checked (see ``modelguard.mbom`` evidence levels).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = MANIFEST_SCHEMA_VERSION
    artifact_type: Literal["file", "directory"]
    algorithm: Literal["sha256"] = "sha256"
    digest: str

    # Declared identity metadata (optional, caller-supplied)
    model_id: str | None = None
    artifact_name: str | None = None
    version: str | None = None
    format: str | None = None
    framework: str | None = None
    license: str | None = None
    creator: str | None = None
    source_location: str | None = None

    files: tuple[ManifestFileEntry, ...] = Field(default_factory=tuple)

    def canonical_json(self) -> bytes:
        """Return the exact bytes that get hashed/signed for this
        manifest: recursively sorted keys and no insignificant
        whitespace, so the same logical manifest always serializes to
        the same bytes regardless of field construction order.
        """
        data = self.model_dump(mode="json", exclude_none=True)
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
