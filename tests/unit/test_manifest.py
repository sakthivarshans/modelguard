from __future__ import annotations

from pathlib import Path

from modelguard.manifest.builder import DeclaredMetadata, build_manifest


def test_build_manifest_for_file(tmp_path: Path) -> None:
    f = tmp_path / "model.bin"
    f.write_bytes(b"weights")

    m = build_manifest(f, DeclaredMetadata(model_id="demo", version="1.0.0"))

    assert m.artifact_type == "file"
    assert m.model_id == "demo"
    assert m.version == "1.0.0"
    assert len(m.digest) == 64  # sha256 hex length


def test_build_manifest_for_directory_includes_file_entries(tmp_path: Path) -> None:
    root = tmp_path / "model"
    root.mkdir()
    (root / "config.json").write_text("{}")
    (root / "weights.bin").write_bytes(b"abc")

    m = build_manifest(root)

    assert m.artifact_type == "directory"
    assert len(m.files) == 2
    assert {f.path for f in m.files} == {"config.json", "weights.bin"}


def test_manifest_canonical_json_is_stable(tmp_path: Path) -> None:
    f = tmp_path / "model.bin"
    f.write_bytes(b"weights")

    m1 = build_manifest(f, DeclaredMetadata(model_id="demo"))
    m2 = build_manifest(f, DeclaredMetadata(model_id="demo"))

    assert m1.canonical_json() == m2.canonical_json()


def test_manifest_defaults_artifact_name_to_path_name(tmp_path: Path) -> None:
    f = tmp_path / "classifier.bin"
    f.write_bytes(b"data")

    m = build_manifest(f)

    assert m.artifact_name == "classifier.bin"
