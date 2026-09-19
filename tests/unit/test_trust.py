from __future__ import annotations

import pytest

from modelguard.exceptions import TrustConfigurationError
from modelguard.sdk import ModelGuard
from modelguard.signing.keys import generate_keypair
from modelguard.signing.trust import normalize_fingerprints, public_key_fingerprint
from tests.conftest import SignedModel, build_signed_model, make_fingerprint

GOOD = "a" * 64


def test_normalize_accepts_prefix_and_uppercase() -> None:
    assert normalize_fingerprints([f"SHA256:{GOOD.upper()}"]) == frozenset({GOOD})


@pytest.mark.parametrize("bad", ["", "abc", "g" * 64, "a" * 63, "a" * 65, "sha256:"])
def test_normalize_rejects_malformed_fingerprints(bad: str) -> None:
    with pytest.raises(TrustConfigurationError):
        normalize_fingerprints([bad])


def test_normalize_rejects_empty_set() -> None:
    with pytest.raises(TrustConfigurationError):
        normalize_fingerprints([])


def test_public_key_fingerprint_rejects_non_hex() -> None:
    with pytest.raises(TrustConfigurationError):
        public_key_fingerprint("not-hex")


def test_guard_rejects_empty_trust_set() -> None:
    with pytest.raises(TrustConfigurationError):
        ModelGuard(trusted_key_fingerprints=[])


def test_verify_without_trust_roots_reports_signer_not_checked(signed_model: SignedModel) -> None:
    result = ModelGuard().verify(signed_model.artifact, signed_model.mbom_path, signed_model.sig_path)
    assert result.allowed
    assert result.signer_trusted is None  # NOT True: nothing was checked


def test_verify_with_matching_fingerprint_is_trusted(signed_model: SignedModel) -> None:
    guard = ModelGuard(trusted_key_fingerprints=[signed_model.fingerprint])
    result = guard.verify(signed_model.artifact, signed_model.mbom_path, signed_model.sig_path)
    assert result.allowed
    assert result.signer_trusted is True


def test_verify_denies_a_valid_signature_from_an_untrusted_key(signed_model: SignedModel) -> None:
    other = make_fingerprint(generate_keypair("someone-else"))
    guard = ModelGuard(trusted_key_fingerprints=[other])
    result = guard.verify(signed_model.artifact, signed_model.mbom_path, signed_model.sig_path)
    assert result.signature_valid
    assert result.signer_trusted is False
    assert not result.allowed
    assert any("not in the configured set of trusted key fingerprints" in r for r in result.reasons)


def test_attacker_resigning_with_own_key_is_denied(tmp_path_factory: pytest.TempPathFactory) -> None:
    """The scenario that motivated trust roots: a tampered model re-signed
    by the attacker verifies cryptographically but must not be trusted."""
    victim_key = generate_keypair("publisher@example.com")
    root = tmp_path_factory.mktemp("attack")
    legit = build_signed_model(root / "legit", keypair=victim_key)

    attacker = build_signed_model(root / "attacker")  # different, attacker-generated key
    (attacker.artifact / "weights.bin").write_bytes(b"backdoored")
    # attacker re-signs their tampered artifact with their own key
    from modelguard.manifest.builder import DeclaredMetadata

    guard = ModelGuard()
    manifest = guard.build_manifest(
        attacker.artifact, DeclaredMetadata(model_id="demo", version="1.0.0", license="Apache-2.0")
    )
    mbom = guard.generate_mbom(manifest)
    envelope = guard.sign(manifest, mbom, attacker.keypair)
    attacker.mbom_path.write_text(mbom.model_dump_json(indent=2))
    attacker.sig_path.write_text(envelope.to_json())

    verifier = ModelGuard(trusted_key_fingerprints=[legit.fingerprint])
    result = verifier.verify(attacker.artifact, attacker.mbom_path, attacker.sig_path)

    assert result.signature_valid and result.digest_matches  # cryptographically fine...
    assert result.signer_trusted is False  # ...but not a key we trust
    assert not result.allowed
