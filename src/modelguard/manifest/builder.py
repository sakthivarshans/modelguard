"""Build a canonical Manifest from a hashed artifact plus declared metadata."""

from __future__ import annotations

from pathlib import Path

from modelguard.hashing.digest import ArtifactDigest, hash_artifact
from modelguard.manifest.models import Manifest, ManifestFileEntry


class DeclaredMetadata:
    """Caller-supplied metadata to attach to a manifest.

    Every field here is DECLARED evidence: ModelGuard has not verified
    that a ``model_id`` of "resnet50-finetuned" actually corresponds to
    the given artifact, only that the caller said so.
    """

    __slots__ = (
        "artifact_name",
        "creator",
        "format",
        "framework",
        "license",
        "model_id",
        "source_location",
        "version",
    )

    def __init__(
        self,
        *,
        model_id: str | None = None,
        artifact_name: str | None = None,
        version: str | None = None,
        format: str | None = None,
        framework: str | None = None,
        license: str | None = None,
        creator: str | None = None,
        source_location: str | None = None,
    ) -> None:
        self.model_id = model_id
        self.artifact_name = artifact_name
        self.version = version
        self.format = format
        self.framework = framework
        self.license = license
        self.creator = creator
        self.source_location = source_location


def build_manifest(
    path: Path,
    metadata: DeclaredMetadata | None = None,
    *,
    precomputed_digest: ArtifactDigest | None = None,
) -> Manifest:
    """Inspect ``path``, hash it, and build a canonical Manifest.

    Pass ``precomputed_digest`` to avoid re-hashing an artifact that has
    already been hashed in the same operation (e.g. by the CLI's
    ``inspect`` step immediately before ``manifest``).
    """
    digest = precomputed_digest or hash_artifact(path)
    meta = metadata or DeclaredMetadata()

    file_entries = tuple(
        ManifestFileEntry(path=f.path, sha256=f.sha256, size=f.size) for f in digest.files
    )

    return Manifest(
        artifact_type=digest.artifact_type,
        algorithm=digest.algorithm,
        digest=digest.digest,
        model_id=meta.model_id,
        artifact_name=meta.artifact_name or path.name,
        version=meta.version,
        format=meta.format,
        framework=meta.framework,
        license=meta.license,
        creator=meta.creator,
        source_location=meta.source_location,
        files=file_entries if digest.artifact_type == "directory" else (),
    )
