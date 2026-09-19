from __future__ import annotations

import os
from pathlib import Path

import pytest

from modelguard.manifest.builder import DeclaredMetadata, build_manifest
from modelguard.mbom.generator import DeclaredProvenance, generate_mbom
from modelguard.scanning import Confidence, MetadataCompletenessScanner, Severity
from modelguard.scanning.secrets import SecretScanner
from modelguard.scanning.unsafe_serialization import UnsafeSerializationScanner

# -- UnsafeSerializationScanner --------------------------------------------


def test_pickle_extension_produces_high_finding(tmp_path: Path) -> None:
    root = tmp_path / "model"
    root.mkdir()
    (root / "weights.pkl").write_bytes(b"anything at all")

    findings = UnsafeSerializationScanner().scan(root, None, None)

    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].confidence == Confidence.HIGH
    assert findings[0].category == "unsafe_deserialization"
    assert findings[0].component == "weights.pkl"


@pytest.mark.parametrize("ext", [".pkl", ".pickle", ".pt", ".pth", ".ckpt", ".joblib", ".dill"])
def test_all_known_pickle_extensions_are_flagged(tmp_path: Path, ext: str) -> None:
    root = tmp_path / "model"
    root.mkdir()
    (root / f"weights{ext}").write_bytes(b"data")

    findings = UnsafeSerializationScanner().scan(root, None, None)

    assert len(findings) == 1


def test_pickle_header_without_matching_extension_produces_medium_finding(tmp_path: Path) -> None:
    root = tmp_path / "model"
    root.mkdir()
    # Protocol-4 pickle header (0x80 0x04) under an unrelated extension.
    (root / "weights.bin").write_bytes(b"\x80\x04" + b"\x00" * 20)

    findings = UnsafeSerializationScanner().scan(root, None, None)

    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].confidence == Confidence.MEDIUM


def test_safe_file_produces_no_finding(tmp_path: Path) -> None:
    root = tmp_path / "model"
    root.mkdir()
    (root / "model.safetensors").write_bytes(b"\x00\x01\x02\x03" * 10)
    (root / "config.json").write_text('{"hidden_size": 768}')

    findings = UnsafeSerializationScanner().scan(root, None, None)

    assert findings == []


def test_scanner_never_unpickles_a_hostile_payload(tmp_path: Path) -> None:
    """A pickle stream whose __reduce__ would execute os.system on load.
    The scanner must complete without ever constructing this object --
    if it did, a marker file would appear on disk.
    """
    import pickle

    marker = tmp_path / "PWNED"

    class _Hostile:
        def __reduce__(self) -> tuple[object, tuple[str]]:
            return (os.system, (f"touch {marker}",))

    root = tmp_path / "model"
    root.mkdir()
    (root / "weights.pkl").write_bytes(pickle.dumps(_Hostile()))

    findings = UnsafeSerializationScanner().scan(root, None, None)

    assert not marker.exists()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_unreadable_file_produces_no_finding_rather_than_a_guess(tmp_path: Path) -> None:
    root = tmp_path / "model"
    root.mkdir()
    f = root / "weights.bin"
    f.write_bytes(b"\x80\x04data")
    f.chmod(0o000)
    try:
        findings = UnsafeSerializationScanner().scan(root, None, None)
    finally:
        f.chmod(0o644)  # so tmp_path cleanup can remove it

    if os.name != "nt" and os.geteuid() != 0:  # root ignores chmod restrictions
        assert findings == []


# -- SecretScanner ----------------------------------------------------------


def test_aws_key_pattern_is_flagged_critical(tmp_path: Path) -> None:
    root = tmp_path / "model"
    root.mkdir()
    (root / "config.txt").write_text("AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\n")

    findings = SecretScanner().scan(root, None, None)

    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].category == "aws_access_key_id"
    # Never echo the actual matched secret text.
    assert "AKIA" not in (findings[0].evidence or "")
    assert "AKIA" not in findings[0].message


def test_pem_private_key_header_is_flagged_critical(tmp_path: Path) -> None:
    root = tmp_path / "model"
    root.mkdir()
    (root / "key.pem").write_text("-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n")

    findings = SecretScanner().scan(root, None, None)

    assert any(f.category == "pem_private_key" and f.severity == Severity.CRITICAL for f in findings)


def test_github_pat_is_flagged_high(tmp_path: Path) -> None:
    root = tmp_path / "model"
    root.mkdir()
    (root / "notes.txt").write_text("token: ghp_" + "a" * 36)

    findings = SecretScanner().scan(root, None, None)

    assert any(f.category == "github_pat" and f.severity == Severity.HIGH for f in findings)


def test_ordinary_text_produces_no_finding(tmp_path: Path) -> None:
    root = tmp_path / "model"
    root.mkdir()
    (root / "README.md").write_text("This model classifies images of cats and dogs.")

    findings = SecretScanner().scan(root, None, None)

    assert findings == []


def test_binary_file_is_skipped(tmp_path: Path) -> None:
    root = tmp_path / "model"
    root.mkdir()
    # Null byte forces the "looks binary" skip even though the string
    # AKIA... below would otherwise match.
    (root / "weights.bin").write_bytes(b"\x00\x01AKIAABCDEFGHIJKLMNOP")

    findings = SecretScanner().scan(root, None, None)

    assert findings == []


def test_oversized_file_is_skipped(tmp_path: Path) -> None:
    root = tmp_path / "model"
    root.mkdir()
    big = root / "big.txt"
    with big.open("w") as fh:
        fh.write("AKIAABCDEFGHIJKLMNOP\n")
        fh.write("x" * (3 * 1024 * 1024))

    findings = SecretScanner().scan(root, None, None)

    assert findings == []


# -- MetadataCompletenessScanner --------------------------------------------


def test_returns_nothing_when_neither_manifest_nor_mbom_supplied(tmp_path: Path) -> None:
    root = tmp_path / "model"
    root.mkdir()
    (root / "weights.bin").write_bytes(b"data")

    findings = MetadataCompletenessScanner().scan(root, None, None)

    assert findings == []


def test_flags_missing_license_lineage_and_identity(tmp_path: Path) -> None:
    root = tmp_path / "model"
    root.mkdir()
    (root / "weights.bin").write_bytes(b"data")

    manifest = build_manifest(root, DeclaredMetadata())
    bom = generate_mbom(manifest)

    findings = MetadataCompletenessScanner().scan(root, manifest, bom)

    categories = {(f.component, f.severity) for f in findings}
    assert ("license", Severity.LOW) in categories
    assert ("parent_models", Severity.INFO) in categories
    assert all(f.severity in (Severity.INFO, Severity.LOW) for f in findings)


def test_complete_metadata_produces_no_finding(tmp_path: Path) -> None:
    root = tmp_path / "model"
    root.mkdir()
    (root / "weights.bin").write_bytes(b"data")

    manifest = build_manifest(
        root, DeclaredMetadata(model_id="demo", version="1.0.0", license="Apache-2.0")
    )
    bom = generate_mbom(
        manifest, DeclaredProvenance(parent_models=["base@sha256:abc"], license="Apache-2.0")
    )

    findings = MetadataCompletenessScanner().scan(root, manifest, bom)

    assert findings == []


# -- symlink handling (shared _walk helper) ---------------------------------


@pytest.mark.skipif(os.name == "nt", reason="symlinks require special privileges on Windows")
def test_symlinked_file_produces_low_skip_finding_not_a_crash(tmp_path: Path) -> None:
    root = tmp_path / "model"
    root.mkdir()
    (root / "real.bin").write_bytes(b"data")
    outside = tmp_path / "outside.bin"
    outside.write_text("AKIAABCDEFGHIJKLMNOP")
    (root / "link.bin").symlink_to(outside)

    findings = SecretScanner().scan(root, None, None)

    # The symlink is skipped (reported, not followed) -- its target's
    # secret must never show up in the results.
    assert not any(f.category == "aws_access_key_id" for f in findings)
    assert any(f.category == "scan_skipped" and f.severity == Severity.LOW for f in findings)
