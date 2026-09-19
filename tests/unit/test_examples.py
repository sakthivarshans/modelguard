"""Tests for the shipped CI/Docker/admission examples.

The workflow and Dockerfile cannot be executed here (no GitHub runner,
no Docker daemon), so they get static checks for the security-relevant
properties the docs claim. The entrypoint and deploy gate are real
scripts and are exercised behaviorally.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from tests.conftest import SignedModel

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "examples"
ENTRYPOINT = EXAMPLES / "docker" / "entrypoint.sh"
GATE = EXAMPLES / "admission" / "deploy_gate.py"


def _env(**extra: str) -> dict[str, str]:
    bin_dir = str(Path(sys.executable).parent)
    env = {"PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "HOME": os.environ.get("HOME", "/tmp")}
    env.update(extra)
    return env


# -- GitHub Actions workflow (static) ---------------------------------------


@pytest.fixture(scope="module")
def workflow() -> dict[str, object]:
    loaded = yaml.safe_load((EXAMPLES / "ci" / "github-actions-verify-model.yml").read_text())
    assert isinstance(loaded, dict)
    return loaded


def test_workflow_is_valid_yaml_with_least_privilege(workflow: dict[str, object]) -> None:
    assert workflow["permissions"] == {"contents": "read"}
    # PyYAML (YAML 1.1) parses the bare key `on` as boolean True.
    triggers = workflow.get("on", workflow.get(True))
    assert isinstance(triggers, dict)
    assert "pull_request_target" not in triggers


def test_workflow_takes_trust_from_variables_and_policy_from_base(workflow: dict[str, object]) -> None:
    text = (EXAMPLES / "ci" / "github-actions-verify-model.yml").read_text()
    assert "--trusted-fingerprint" in text
    assert "vars.MODELGUARD_TRUSTED_FINGERPRINT" in text
    assert "github.event.pull_request.base.sha" in text
    assert "trusted/$POLICY_PATH" in text


def test_workflow_refuses_to_run_unconfigured() -> None:
    text = (EXAMPLES / "ci" / "github-actions-verify-model.yml").read_text()
    assert "REPLACE_WITH_" in text and "exit 1" in text


# -- Dockerfile (static) ---------------------------------------------------


def test_dockerfile_forces_build_gate_and_makes_no_verified_label() -> None:
    text = (ROOT / "examples" / "docker" / "Dockerfile").read_text()
    assert "COPY --from=verify /opt/model" in text
    assert "modelguard policy check" in text
    lines = [line for line in text.splitlines() if not line.lstrip().startswith("#")]
    assert not any("verification.status" in line for line in lines)
    for label in ("org.modelguard.model.id", "org.modelguard.model.digest", "org.modelguard.mbom.digest"):
        assert label in text
    assert 'ENTRYPOINT ["/usr/local/bin/modelguard-entrypoint"]' in text


# -- entrypoint.sh (behavioral) --------------------------------------------


def _run_entrypoint(m: SignedModel, **env: str) -> subprocess.CompletedProcess[str]:
    base = {
        "MODELGUARD_MODEL_DIR": str(m.artifact),
        "MODELGUARD_BOM": str(m.mbom_path),
        "MODELGUARD_SIGNATURE": str(m.sig_path),
        "MODELGUARD_POLICY": str(m.policy_path),
    }
    base.update(env)
    return subprocess.run(
        ["sh", str(ENTRYPOINT), "echo", "APPLICATION-STARTED"],
        env=_env(**base),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def test_entrypoint_starts_the_application_when_verification_passes(signed_model: SignedModel) -> None:
    done = _run_entrypoint(signed_model, MODELGUARD_TRUSTED_FINGERPRINT=signed_model.fingerprint)
    assert done.returncode == 0, done.stderr
    assert "APPLICATION-STARTED" in done.stdout


def test_entrypoint_refuses_without_a_trust_root(signed_model: SignedModel) -> None:
    done = _run_entrypoint(signed_model)
    assert done.returncode == 78
    assert "APPLICATION-STARTED" not in done.stdout


def test_entrypoint_refuses_an_untrusted_signer(signed_model: SignedModel) -> None:
    done = _run_entrypoint(signed_model, MODELGUARD_TRUSTED_FINGERPRINT="f" * 64)
    assert done.returncode == 78
    assert "APPLICATION-STARTED" not in done.stdout


def test_entrypoint_refuses_a_tampered_model(signed_model: SignedModel) -> None:
    (signed_model.artifact / "weights.bin").write_bytes(b"tampered")
    done = _run_entrypoint(signed_model, MODELGUARD_TRUSTED_FINGERPRINT=signed_model.fingerprint)
    assert done.returncode == 78
    assert "APPLICATION-STARTED" not in done.stdout


def test_entrypoint_refuses_when_a_required_file_is_missing(signed_model: SignedModel) -> None:
    signed_model.sig_path.unlink()
    done = _run_entrypoint(signed_model, MODELGUARD_TRUSTED_FINGERPRINT=signed_model.fingerprint)
    assert done.returncode != 0
    assert "APPLICATION-STARTED" not in done.stdout


# -- deploy_gate.py (behavioral) -------------------------------------------


def _run_gate(m: SignedModel, fingerprint: str | None) -> subprocess.CompletedProcess[str]:
    cmd = [sys.executable, str(GATE), str(m.artifact), str(m.mbom_path), str(m.sig_path), str(m.policy_path),
           "--actor", "ci"]  # fmt: skip
    if fingerprint:
        cmd += ["--trusted-fingerprint", fingerprint]
    return subprocess.run(cmd, env=_env(), capture_output=True, text=True, timeout=60, check=False)


def test_deploy_gate_admits_then_blocks_after_tampering(signed_model: SignedModel) -> None:
    ok = _run_gate(signed_model, signed_model.fingerprint)
    assert ok.returncode == 0 and "ADMITTED demo@1.0.0" in ok.stdout
    assert "revocation was NOT checked" in ok.stderr  # honest about coverage

    (signed_model.artifact / "weights.bin").write_bytes(b"tampered")
    bad = _run_gate(signed_model, signed_model.fingerprint)
    assert bad.returncode == 1 and "BLOCKED" in bad.stderr


def test_deploy_gate_blocks_without_a_trust_root(signed_model: SignedModel) -> None:
    done = _run_gate(signed_model, None)
    assert done.returncode == 1 and "trust root" in done.stderr
