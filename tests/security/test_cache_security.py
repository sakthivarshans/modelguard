from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from modelguard.cache import CachedHasher
from modelguard.cache import digest_cache as dc
from modelguard.hashing.digest import hash_artifact
from modelguard.manifest.builder import DeclaredMetadata
from modelguard.mbom.models import MLBOM
from modelguard.sdk import ModelGuard
from tests.conftest import SignedModel

posix_only = pytest.mark.skipif(os.name != "posix", reason="cache is bypassed off POSIX")


@pytest.fixture(autouse=True)
def _no_racy_margin(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dc, "RACY_MARGIN_NS", 0)


def _warm(signed: SignedModel, cache_dir: Path) -> ModelGuard:
    guard = ModelGuard(cache_dir=cache_dir, trusted_key_fingerprints=[signed.fingerprint])
    first = guard.verify(signed.artifact, signed.mbom_path, signed.sig_path)
    assert first.allowed and not first.digest_from_cache
    time.sleep(0.01)
    second = guard.verify(signed.artifact, signed.mbom_path, signed.sig_path)
    assert second.allowed and second.digest_from_cache  # cache really is in play
    return guard


@posix_only
def test_cached_verification_never_overrides_a_new_revocation(
    signed_model: SignedModel, tmp_path: Path
) -> None:
    """The core requirement from the product doc: a warm cache must not
    let a since-revoked model through."""
    storage = tmp_path / "store"
    guard = ModelGuard(
        storage_root=storage,
        cache_dir=tmp_path / "cache",
        trusted_key_fingerprints=[signed_model.fingerprint],
    )
    manifest = guard.build_manifest(
        signed_model.artifact, DeclaredMetadata(model_id="demo", version="1.0.0")
    )
    guard.register(manifest, MLBOM.model_validate(json.loads(signed_model.mbom_path.read_text())), "dev")

    args = (signed_model.artifact, signed_model.mbom_path, signed_model.sig_path)
    guard.verify(*args)
    warm = guard.verify(*args)
    assert warm.allowed and warm.digest_from_cache

    guard.revoke("demo", "1.0.0", actor="security", reason="compromised")

    after = guard.verify(*args)
    assert after.digest_from_cache  # cache still used for hashing...
    assert after.revoked and not after.allowed  # ...but revocation is always live


@posix_only
def test_cached_verification_still_detects_tampering(signed_model: SignedModel, tmp_path: Path) -> None:
    guard = _warm(signed_model, tmp_path / "cache")
    (signed_model.artifact / "weights.bin").write_bytes(b"backdoor")
    result = guard.verify(signed_model.artifact, signed_model.mbom_path, signed_model.sig_path)
    assert not result.allowed and not result.digest_matches and not result.digest_from_cache


@posix_only
def test_cached_verification_still_enforces_trust_roots(signed_model: SignedModel, tmp_path: Path) -> None:
    _warm(signed_model, tmp_path / "cache")
    stranger = ModelGuard(cache_dir=tmp_path / "cache", trusted_key_fingerprints=["b" * 64])
    result = stranger.verify(signed_model.artifact, signed_model.mbom_path, signed_model.sig_path)
    assert result.digest_from_cache and result.signer_trusted is False and not result.allowed


@posix_only
def test_group_writable_cache_file_is_ignored(signed_model: SignedModel, tmp_path: Path) -> None:
    cache_dir = tmp_path / "cache"
    _warm(signed_model, cache_dir)
    (cache_dir / dc.CACHE_FILENAME).chmod(0o664)
    guard = ModelGuard(cache_dir=cache_dir)
    result = guard.verify(signed_model.artifact, signed_model.mbom_path, signed_model.sig_path)
    assert not result.digest_from_cache and result.digest_matches


@posix_only
def test_symlinked_cache_file_is_ignored(signed_model: SignedModel, tmp_path: Path) -> None:
    cache_dir = tmp_path / "cache"
    _warm(signed_model, cache_dir)
    real = cache_dir / dc.CACHE_FILENAME
    moved = tmp_path / "elsewhere.json"
    real.rename(moved)
    real.symlink_to(moved)
    result = CachedHasher(cache_dir).hash(signed_model.artifact)
    assert not result.from_cache


@posix_only
def test_cache_entry_from_a_different_path_is_not_reused(tmp_path: Path) -> None:
    a = tmp_path / "a"
    a.mkdir()
    (a / "w").write_bytes(b"same")
    b = tmp_path / "b"
    b.mkdir()
    (b / "w").write_bytes(b"different")
    hasher = CachedHasher(tmp_path / "cache")
    hasher.hash(a)
    result = hasher.hash(b)
    assert not result.from_cache and result.digest == hash_artifact(b)


def test_check_policy_hashes_the_artifact_only_once(
    signed_model: SignedModel, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression for the redundant second hash in run_scanners."""
    import modelguard.hashing.digest as digest_mod
    import modelguard.scanning.runner as runner_mod
    import modelguard.sdk as sdk_mod

    calls = 0
    real = digest_mod.hash_artifact

    def counting(path: Path):  # type: ignore[no-untyped-def]
        nonlocal calls
        calls += 1
        return real(path)

    monkeypatch.setattr(sdk_mod, "hash_artifact", counting)
    monkeypatch.setattr(runner_mod, "hash_artifact", counting)
    monkeypatch.setattr(digest_mod, "hash_artifact", counting)
    import modelguard.signing.verifier as verifier_mod

    monkeypatch.setattr(verifier_mod, "hash_artifact", counting)

    guard = ModelGuard(trusted_key_fingerprints=[signed_model.fingerprint])
    # verifier's default arg was bound at import; SDK passes its own closure calling sdk_mod.hash_artifact
    guard.check_policy(
        signed_model.artifact, signed_model.mbom_path, signed_model.sig_path, signed_model.policy_path
    )
    assert calls == 1
