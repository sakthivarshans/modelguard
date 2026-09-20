"""Security tests for whole-artifact upload/download, incl. hostile manifests."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest

from modelguard.exceptions import UnsafePathError
from modelguard.hashing.digest import hash_artifact
from modelguard.storage import (
    ArtifactIntegrityError,
    ArtifactStoreError,
    LocalBlobStore,
    download_artifact,
    upload_artifact,
)
from tests.conftest import BlobBackend


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _model(root: Path) -> Path:
    m = root / "model"
    (m / "sub" / "deep").mkdir(parents=True)
    (m / "weights.bin").write_bytes(b"W" * 200_000)
    (m / "config.json").write_text('{"a": 1}')
    (m / "sub" / "tok.json").write_text("tok")
    (m / "sub" / "deep" / "dup.bin").write_bytes(b"W" * 200_000)  # duplicate content
    return m


def _stage_leftovers(parent: Path) -> list[str]:
    return [p.name for p in parent.iterdir() if p.name.startswith(".mg-stage")]


# -- happy paths ----------------------------------------------------------------


def test_directory_roundtrip_on_both_backends(blob_backend: BlobBackend, tmp_path: Path) -> None:
    model = _model(tmp_path)
    digest = upload_artifact(blob_backend.store, model)

    out = tmp_path / "restored" / "model"
    download_artifact(blob_backend.store, f"sha256:{digest.digest}", "directory", out)

    assert hash_artifact(out).digest == digest.digest
    assert (out / "sub" / "deep" / "dup.bin").read_bytes() == b"W" * 200_000
    assert _stage_leftovers(out.parent) == []


def test_identical_files_are_stored_once(tmp_path: Path) -> None:
    store = LocalBlobStore(tmp_path / "s")
    upload_artifact(store, _model(tmp_path))
    blobs = [p for p in (tmp_path / "s").rglob("*") if p.is_file()]
    # 3 distinct file contents + 1 manifest, although 4 files exist.
    assert len(blobs) == 4


def test_single_file_roundtrip(blob_backend: BlobBackend, tmp_path: Path) -> None:
    f = tmp_path / "w.safetensors"
    f.write_bytes(os.urandom(50_000))
    digest = upload_artifact(blob_backend.store, f)
    out = tmp_path / "out" / "w.safetensors"
    download_artifact(blob_backend.store, f"sha256:{digest.digest}", "file", out)
    assert out.read_bytes() == f.read_bytes()


def test_downloads_are_private_by_default(tmp_path: Path) -> None:
    store = LocalBlobStore(tmp_path / "s")
    digest = upload_artifact(store, _model(tmp_path))
    out = tmp_path / "o"
    download_artifact(store, f"sha256:{digest.digest}", "directory", out)
    assert stat.S_IMODE((out / "weights.bin").stat().st_mode) == 0o600
    assert stat.S_IMODE(out.stat().st_mode) == 0o700


# -- tampering -------------------------------------------------------------------


def test_tampered_file_blob_fails_and_leaves_nothing(blob_backend: BlobBackend, tmp_path: Path) -> None:
    model = _model(tmp_path)
    digest = upload_artifact(blob_backend.store, model)
    blob_backend.tamper(digest.files[-1].sha256, b"backdoor" * 10)

    out = tmp_path / "restored" / "model"
    with pytest.raises(ArtifactIntegrityError):
        download_artifact(blob_backend.store, f"sha256:{digest.digest}", "directory", out)
    assert not out.exists()
    assert _stage_leftovers(out.parent) == []


def test_tampered_manifest_blob_fails(blob_backend: BlobBackend, tmp_path: Path) -> None:
    digest = upload_artifact(blob_backend.store, _model(tmp_path))
    blob_backend.tamper(digest.digest, b'{"algorithm":"sha256","files":[]}')
    out = tmp_path / "o"
    with pytest.raises(ArtifactIntegrityError):
        download_artifact(blob_backend.store, f"sha256:{digest.digest}", "directory", out)
    assert not out.exists()


def test_failed_download_never_touches_a_preexisting_destination(tmp_path: Path) -> None:
    store = LocalBlobStore(tmp_path / "s")
    digest = upload_artifact(store, _model(tmp_path))
    dest = tmp_path / "precious"
    dest.mkdir()
    (dest / "keep.txt").write_text("keep me")
    with pytest.raises(ArtifactStoreError, match="already exists"):
        download_artifact(store, f"sha256:{digest.digest}", "directory", dest)
    assert (dest / "keep.txt").read_text() == "keep me"


# -- hostile (but correctly hashed) manifests ---------------------------------------


def _publish_manifest(store: LocalBlobStore, tmp_path: Path, doc: Any, *, canonical: bool = False) -> str:
    """Store `doc` as a manifest blob keyed by its own hash, as a malicious
    signer/publisher could, and return the artifact digest string."""
    raw = (
        json.dumps(doc, sort_keys=True, separators=(",", ":"))
        if canonical
        else json.dumps(doc, indent=2)
    ).encode()
    src = tmp_path / "m.json"
    src.write_bytes(raw)
    store.put(_sha(raw), src)
    return f"sha256:{_sha(raw)}"


def _entry(path: str, data: bytes = b"evil", store: LocalBlobStore | None = None, tmp: Path | None = None) -> dict[str, Any]:
    if store is not None and tmp is not None:
        f = tmp / "blob.bin"
        f.write_bytes(data)
        store.put(_sha(data), f)
    return {"path": path, "sha256": _sha(data), "size": len(data)}


@pytest.mark.parametrize(
    "bad_path",
    ["../evil", "a/../../evil", "/abs/evil", "a\\b", "", ".", "a//b", "a/./b", "x\x00y", "a/" + "s" * 300],
)
def test_malicious_paths_in_a_correctly_hashed_manifest_are_refused(tmp_path: Path, bad_path: str) -> None:
    store = LocalBlobStore(tmp_path / "s")
    digest = _publish_manifest(
        store, tmp_path, {"algorithm": "sha256", "files": [_entry(bad_path, store=store, tmp=tmp_path)]}, canonical=True
    )
    dest = tmp_path / "out" / "model"
    with pytest.raises(ArtifactIntegrityError, match="Unsafe path"):
        download_artifact(store, digest, "directory", dest)
    assert not (tmp_path / "evil").exists() and not (tmp_path / "out" / "evil").exists()
    assert not dest.exists()
    assert _stage_leftovers(dest.parent) == []


@pytest.mark.parametrize(
    ("doc_factory", "message"),
    [
        (lambda e: {"algorithm": "sha256", "files": [e("a"), e("a")]}, "Duplicate"),
        (lambda e: {"algorithm": "sha256", "files": [e("a"), e("a/b", b"other")]}, "both a file and a directory"),
        (lambda e: {"algorithm": "sha256", "files": []}, "no files"),
        (lambda e: {"algorithm": "md5", "files": [e("a")]}, "unexpected structure"),
        (lambda e: {"algorithm": "sha256", "files": [e("a")], "extra": 1}, "unexpected structure"),
        (lambda e: {"algorithm": "sha256", "files": [{**e("a"), "size": True}]}, "invalid size"),
        (lambda e: {"algorithm": "sha256", "files": [{**e("a"), "size": -1}]}, "invalid size"),
        (lambda e: {"algorithm": "sha256", "files": [{**e("a"), "sha256": "XYZ"}]}, "invalid SHA-256"),
        (lambda e: {"algorithm": "sha256", "files": [{"path": "a"}]}, "unexpected structure"),
    ],
)
def test_structurally_invalid_manifests_are_refused(tmp_path: Path, doc_factory: Any, message: str) -> None:
    store = LocalBlobStore(tmp_path / "s")

    def entry(path: str, data: bytes = b"evil") -> dict[str, Any]:
        return _entry(path, data, store, tmp_path)

    digest = _publish_manifest(store, tmp_path, doc_factory(entry), canonical=True)
    with pytest.raises(ArtifactIntegrityError, match=message):
        download_artifact(store, digest, "directory", tmp_path / "o")


def test_non_canonical_manifest_is_refused_even_though_its_hash_matches(tmp_path: Path) -> None:
    store = LocalBlobStore(tmp_path / "s")
    doc = {"algorithm": "sha256", "files": [_entry("a", store=store, tmp=tmp_path)]}
    digest = _publish_manifest(store, tmp_path, doc, canonical=False)  # pretty-printed
    with pytest.raises(ArtifactIntegrityError, match="canonical"):
        download_artifact(store, digest, "directory", tmp_path / "o")


def test_declared_size_must_match_the_blob(tmp_path: Path) -> None:
    store = LocalBlobStore(tmp_path / "s")
    entry = _entry("a", b"12345", store, tmp_path)
    entry["size"] = 3
    digest = _publish_manifest(store, tmp_path, {"algorithm": "sha256", "files": [entry]}, canonical=True)
    out = tmp_path / "out" / "m"
    with pytest.raises(ArtifactIntegrityError):
        download_artifact(store, digest, "directory", out)
    assert not out.exists() and _stage_leftovers(out.parent) == []


def test_file_count_and_total_size_limits(tmp_path: Path) -> None:
    store = LocalBlobStore(tmp_path / "s")
    digest = upload_artifact(store, _model(tmp_path))
    with pytest.raises(ArtifactIntegrityError, match="more than 2 files"):
        download_artifact(store, f"sha256:{digest.digest}", "directory", tmp_path / "a", max_files=2)
    with pytest.raises(ArtifactIntegrityError, match="total size"):
        download_artifact(store, f"sha256:{digest.digest}", "directory", tmp_path / "b", max_total_bytes=1000)
    assert not (tmp_path / "a").exists() and not (tmp_path / "b").exists()


@pytest.mark.parametrize("bad", ["md5:" + "a" * 64, "sha256:xyz", "sha256:" + "A" * 64, "a" * 64, ""])
def test_malformed_artifact_digest_is_refused(tmp_path: Path, bad: str) -> None:
    with pytest.raises(ArtifactStoreError):
        download_artifact(LocalBlobStore(tmp_path / "s"), bad, "directory", tmp_path / "o")


def test_unknown_artifact_type_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ArtifactStoreError):
        download_artifact(LocalBlobStore(tmp_path / "s"), "sha256:" + "a" * 64, "archive", tmp_path / "o")


# -- upload safety -------------------------------------------------------------------


def test_upload_refuses_symlinks_and_uploads_nothing(tmp_path: Path) -> None:
    model = _model(tmp_path)
    (model / "sneaky").symlink_to(tmp_path / "outside.txt")
    store = LocalBlobStore(tmp_path / "s")
    with pytest.raises(UnsafePathError):
        upload_artifact(store, model)
    assert not (tmp_path / "s").exists()


def test_file_modified_between_hashing_and_upload_is_refused(tmp_path: Path) -> None:
    model = _model(tmp_path)
    real = LocalBlobStore(tmp_path / "s")

    class Racy:
        """A store whose put() is preceded by an attacker editing the file."""

        def exists(self, sha: str) -> bool:
            return real.exists(sha)

        def get_to(self, sha: str, dest: Path, *, max_bytes: int) -> None:
            real.get_to(sha, dest, max_bytes=max_bytes)

        def put(self, sha: str, source: Path) -> None:
            if source.name == "config.json":
                source.write_text('{"a": "backdoor"}')
            real.put(sha, source)

    with pytest.raises(ArtifactIntegrityError, match="changed after hashing|claimed SHA-256"):
        upload_artifact(Racy(), model)
    assert not real.exists(_sha(b'{"a": "backdoor"}'))


def test_symlink_swapped_in_after_hashing_is_not_followed_or_uploaded(tmp_path: Path) -> None:
    model = _model(tmp_path)
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP SECRET")
    real = LocalBlobStore(tmp_path / "s")

    class Swapper:
        def exists(self, sha: str) -> bool:
            return real.exists(sha)

        def get_to(self, sha: str, dest: Path, *, max_bytes: int) -> None:
            real.get_to(sha, dest, max_bytes=max_bytes)

        def put(self, sha: str, source: Path) -> None:
            if source.name == "tok.json":
                source.unlink()
                source.symlink_to(secret)
            real.put(sha, source)

    with pytest.raises(ArtifactStoreError):
        upload_artifact(Swapper(), model)
    assert not real.exists(_sha(b"TOP SECRET"))
