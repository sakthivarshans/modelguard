"""Contract every ``BlobStore`` must satisfy (local and S3 run identically)."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from modelguard.storage import ArtifactIntegrityError, ArtifactNotFoundError, ArtifactStoreError
from tests.conftest import BlobBackend


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _src(tmp_path: Path, data: bytes, name: str = "src.bin") -> Path:
    p = tmp_path / name
    p.write_bytes(data)
    return p


def _leftovers(directory: Path) -> list[str]:
    return sorted(p.name for p in directory.iterdir() if ".part" in p.name)


@pytest.mark.parametrize("size", [0, 10, 3 * 1024 * 1024 + 7])
def test_roundtrip(blob_backend: BlobBackend, tmp_path: Path, size: int) -> None:
    data = (b"x" * size) if size < 100 else bytes(range(256)) * (size // 256 + 1)
    data = data[:size]
    store = blob_backend.store
    assert not store.exists(_sha(data))
    store.put(_sha(data), _src(tmp_path, data))
    assert store.exists(_sha(data))

    out = tmp_path / "out.bin"
    store.get_to(_sha(data), out, max_bytes=size + 1)
    assert out.read_bytes() == data


def test_get_missing_raises_not_found(blob_backend: BlobBackend, tmp_path: Path) -> None:
    with pytest.raises(ArtifactNotFoundError):
        blob_backend.store.get_to(_sha(b"absent"), tmp_path / "o", max_bytes=10)
    assert not (tmp_path / "o").exists()


def test_put_with_wrong_digest_is_refused_and_stores_nothing(blob_backend: BlobBackend, tmp_path: Path) -> None:
    claimed = _sha(b"what the caller claims")
    with pytest.raises(ArtifactIntegrityError):
        blob_backend.store.put(claimed, _src(tmp_path, b"what is actually there"))
    assert not blob_backend.store.exists(claimed)
    assert blob_backend.stored_count() == 0


def test_tampered_blob_is_detected_and_leaves_nothing(blob_backend: BlobBackend, tmp_path: Path) -> None:
    data = b"genuine model weights" * 100
    blob_backend.store.put(_sha(data), _src(tmp_path, data))
    blob_backend.tamper(_sha(data), b"backdoored weights" * 100)

    out_dir = tmp_path / "dl"
    out_dir.mkdir()
    with pytest.raises(ArtifactIntegrityError, match="do not match"):
        blob_backend.store.get_to(_sha(data), out_dir / "w.bin", max_bytes=10**6)
    assert list(out_dir.iterdir()) == []  # no file, no .part temp


def test_size_limit_is_enforced_while_streaming(blob_backend: BlobBackend, tmp_path: Path) -> None:
    data = b"y" * 5000
    blob_backend.store.put(_sha(data), _src(tmp_path, data))
    out_dir = tmp_path / "dl"
    out_dir.mkdir()
    with pytest.raises(ArtifactIntegrityError, match="limit"):
        blob_backend.store.get_to(_sha(data), out_dir / "w.bin", max_bytes=100)
    assert list(out_dir.iterdir()) == []


@pytest.mark.parametrize(
    "bad", ["", "../etc/passwd", "a" * 63, "a" * 65, "A" * 64, "g" * 64, "a" * 63 + "/", " " + "a" * 63]
)
def test_invalid_identifiers_are_rejected_everywhere(blob_backend: BlobBackend, tmp_path: Path, bad: str) -> None:
    src = _src(tmp_path, b"x")
    with pytest.raises(ArtifactStoreError):
        blob_backend.store.exists(bad)
    with pytest.raises(ArtifactStoreError):
        blob_backend.store.put(bad, src)
    with pytest.raises(ArtifactStoreError):
        blob_backend.store.get_to(bad, tmp_path / "o", max_bytes=10)


def test_existing_destination_is_never_overwritten(blob_backend: BlobBackend, tmp_path: Path) -> None:
    data = b"new"
    blob_backend.store.put(_sha(data), _src(tmp_path, data))
    existing = _src(tmp_path, b"precious existing file", "existing.bin")
    with pytest.raises(ArtifactStoreError, match="already exists"):
        blob_backend.store.get_to(_sha(data), existing, max_bytes=10)
    assert existing.read_bytes() == b"precious existing file"


def test_put_refuses_symlink_source_even_when_content_would_match(blob_backend: BlobBackend, tmp_path: Path) -> None:
    real = _src(tmp_path, b"secret-ish content", "real.bin")
    link = tmp_path / "link.bin"
    link.symlink_to(real)
    with pytest.raises(ArtifactStoreError):
        blob_backend.store.put(_sha(b"secret-ish content"), link)
    assert blob_backend.stored_count() == 0


def test_put_refuses_a_directory_source(blob_backend: BlobBackend, tmp_path: Path) -> None:
    with pytest.raises(ArtifactStoreError):
        blob_backend.store.put(_sha(b""), tmp_path)


def test_put_is_idempotent(blob_backend: BlobBackend, tmp_path: Path) -> None:
    data = b"same"
    for _ in range(2):
        blob_backend.store.put(_sha(data), _src(tmp_path, data))
    assert blob_backend.stored_count() == 1
