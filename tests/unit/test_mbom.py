from __future__ import annotations

import json
from pathlib import Path

from modelguard.manifest.builder import DeclaredMetadata, build_manifest
from modelguard.mbom.generator import DeclaredProvenance, generate_mbom
from modelguard.mbom.models import MLBOM, EvidenceLevel


def _manifest(tmp_path: Path):
    f = tmp_path / "model.bin"
    f.write_bytes(b"weights")
    return build_manifest(f, DeclaredMetadata(model_id="demo", version="1.0.0"))


def test_mbom_binds_artifact_digest(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    bom = generate_mbom(manifest)

    assert bom.modelguard.artifact_digest == f"{manifest.algorithm}:{manifest.digest}"


def test_mbom_provenance_fields_are_declared_evidence(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    provenance = DeclaredProvenance(
        parent_models=["base-model@sha256:abc"],
        dataset_references=["dataset-x@sha256:def"],
        training_code_commit="a1b2c3d",
    )

    bom = generate_mbom(manifest, provenance)

    assert bom.modelguard.parent_models[0].value == "base-model@sha256:abc"
    assert bom.modelguard.parent_models[0].evidence == EvidenceLevel.DECLARED
    assert bom.modelguard.dataset_references[0].evidence == EvidenceLevel.DECLARED
    assert bom.modelguard.training_code_commit is not None
    assert bom.modelguard.training_code_commit.evidence == EvidenceLevel.DECLARED


def test_mbom_round_trips_through_json(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    bom = generate_mbom(manifest)

    serialized = bom.to_json()
    restored = MLBOM.model_validate(json.loads(serialized))

    assert restored.modelguard.artifact_digest == bom.modelguard.artifact_digest
    assert restored.serial_number == bom.serial_number


def test_mbom_uses_cyclonedx_envelope_shape(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    bom = generate_mbom(manifest)
    data = json.loads(bom.to_json())

    assert data["bomFormat"] == "CycloneDX"
    assert "specVersion" in data
    assert "serialNumber" in data
    assert "components" in data
