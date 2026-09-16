from __future__ import annotations

from pathlib import Path

import pytest

from modelguard.exceptions import InvalidKeyError, KeyNotFoundError
from modelguard.manifest.builder import DeclaredMetadata, build_manifest
from modelguard.mbom.generator import generate_mbom
from modelguard.signing.keys import (
    generate_keypair,
    load_private_key,
    load_public_key,
    save_keypair,
)
from modelguard.signing.signer import sign_artifact
from modelguard.signing.verifier import check_mbom_digest, check_signature_bytes, verify_artifact


def _signed_fixture(tmp_path: Path):
    f = tmp_path / "model.bin"
    f.write_bytes(b"weights v1")
    manifest = build_manifest(f, DeclaredMetadata(model_id="demo", version="1.0.0"))
    bom = generate_mbom(manifest)
    keypair = generate_keypair("dev@example.com")
    envelope = sign_artifact(manifest, bom, keypair)
    return f, manifest, bom, keypair, envelope


def test_keypair_round_trips_through_disk(tmp_path: Path) -> None:
    keypair = generate_keypair("dev@example.com")
    priv_path, pub_path = save_keypair(keypair, tmp_path)

    assert priv_path.exists()
    assert pub_path.exists()
    # Private key must not be group/world readable.
    mode = priv_path.stat().st_mode & 0o777
    assert mode == 0o600

    loaded = load_private_key(priv_path, "dev@example.com")
    assert loaded.private_key.private_bytes_raw() == keypair.private_key.private_bytes_raw()

    loaded_pub = load_public_key(pub_path)
    assert loaded_pub.public_bytes_raw() == keypair.public_key.public_bytes_raw()


def test_load_private_key_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(KeyNotFoundError):
        load_private_key(tmp_path / "nope.key", "dev@example.com")


def test_load_private_key_rejects_malformed_bytes(tmp_path: Path) -> None:
    bad = tmp_path / "bad.key"
    bad.write_bytes(b"not a real key")
    with pytest.raises(InvalidKeyError):
        load_private_key(bad, "dev@example.com")


def test_sign_and_verify_succeeds_for_untampered_artifact(tmp_path: Path) -> None:
    f, _manifest, bom, _keypair, envelope = _signed_fixture(tmp_path)

    result = verify_artifact(f, bom, envelope)

    assert result.matches
    assert result.current_digest == envelope.payload.artifact_digest


def test_signature_covers_signer_identity(tmp_path: Path) -> None:
    _, _, _, keypair, envelope = _signed_fixture(tmp_path)
    assert envelope.payload.signer_identity == "dev@example.com"
    assert envelope.public_key == keypair.public_key.public_bytes_raw().hex()


# --------------------------------------------------------------------------
# Security / negative tests
# --------------------------------------------------------------------------


def test_tampered_artifact_fails_verification(tmp_path: Path) -> None:
    f, _manifest, bom, _keypair, envelope = _signed_fixture(tmp_path)

    f.write_bytes(b"weights v2 -- tampered")

    from modelguard.exceptions import DigestMismatchError

    with pytest.raises(DigestMismatchError):
        verify_artifact(f, bom, envelope)


def test_tampered_signature_bytes_fail_verification(tmp_path: Path) -> None:
    _f, _manifest, _bom, _keypair, envelope = _signed_fixture(tmp_path)

    # Flip a character in the hex-encoded signature.
    corrupted_sig = ("f" if envelope.signature[0] != "f" else "0") + envelope.signature[1:]
    tampered = envelope.model_copy(update={"signature": corrupted_sig})

    from modelguard.exceptions import SignatureInvalidError

    with pytest.raises(SignatureInvalidError):
        check_signature_bytes(tampered)


def test_tampered_payload_fails_verification(tmp_path: Path) -> None:
    _f, _manifest, _bom, _keypair, envelope = _signed_fixture(tmp_path)

    tampered_payload = envelope.payload.model_copy(update={"model_id": "attacker-model"})
    tampered = envelope.model_copy(update={"payload": tampered_payload})

    from modelguard.exceptions import SignatureInvalidError

    with pytest.raises(SignatureInvalidError):
        check_signature_bytes(tampered)


def test_wrong_public_key_fails_verification(tmp_path: Path) -> None:
    _f, _manifest, _bom, _keypair, envelope = _signed_fixture(tmp_path)

    attacker_keypair = generate_keypair("attacker@example.com")
    forged = envelope.model_copy(
        update={"public_key": attacker_keypair.public_key.public_bytes_raw().hex()}
    )

    from modelguard.exceptions import SignatureInvalidError

    with pytest.raises(SignatureInvalidError):
        check_signature_bytes(forged)


def test_mismatched_mbom_fails_verification(tmp_path: Path) -> None:
    _f, manifest, _bom, _keypair, envelope = _signed_fixture(tmp_path)

    from modelguard.mbom.generator import generate_mbom

    different_bom = generate_mbom(manifest)  # different serial_number/timestamp

    assert not check_mbom_digest(different_bom, envelope)


def test_renamed_file_inside_directory_artifact_is_detected(tmp_path: Path) -> None:
    root = tmp_path / "model"
    root.mkdir()
    (root / "weights.safetensors").write_bytes(b"binary weights")
    (root / "config.json").write_text('{"hidden_size": 768}')

    manifest = build_manifest(root)
    bom = generate_mbom(manifest)
    keypair = generate_keypair("dev@example.com")
    envelope = sign_artifact(manifest, bom, keypair)

    # Same file content, different structure -- e.g. an attacker
    # renaming a malicious file to look like a legitimate one.
    (root / "config.json").rename(root / "weights.safetensors.bak")
    (root / "weights.safetensors.bak").rename(root / "config.json")  # no-op sanity
    (root / "weights.safetensors").rename(root / "renamed.safetensors")

    from modelguard.exceptions import DigestMismatchError

    with pytest.raises(DigestMismatchError):
        verify_artifact(root, bom, envelope)
