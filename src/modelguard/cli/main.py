"""ModelGuard command-line interface.

Implements the Phase 1 slice of the CLI surface described in the
architecture document (inspect, hash, manifest, mbom generate, keygen,
sign, verify) plus the Phase 2 registry/provenance commands (register,
resolve, revoke, lineage). Every command supports ``--format json`` for
CI use and returns a non-zero exit code on failure.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

import click
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from modelguard.exceptions import ModelGuardError
from modelguard.hashing.digest import hash_artifact
from modelguard.manifest.builder import DeclaredMetadata, build_manifest
from modelguard.manifest.models import Manifest
from modelguard.mbom.generator import generate_mbom
from modelguard.mbom.models import MLBOM
from modelguard.policy.loader import PolicyValidationError, load_policy_file
from modelguard.policy.models import Decision
from modelguard.scanning import Finding, ScanReport, Severity, run_scanners
from modelguard.sdk import ModelGuard
from modelguard.signing.keys import (
    generate_keypair,
    load_private_key,
    load_public_key,
    save_keypair,
)
from modelguard.signing.signer import sign_artifact
from modelguard.signing.trust import public_key_fingerprint

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_DENIED = 2
EXIT_REVIEW_REQUIRED = 3
EXIT_QUARANTINE = 4
EXIT_REVOKED = 5

_DECISION_EXIT_CODES: dict[Decision, int] = {
    Decision.ALLOW: EXIT_OK,
    Decision.ALLOW_WITH_WARNINGS: EXIT_OK,
    Decision.REVIEW_REQUIRED: EXIT_REVIEW_REQUIRED,
    Decision.QUARANTINE: EXIT_QUARANTINE,
    Decision.DENY: EXIT_DENIED,
    Decision.REVOKED: EXIT_REVOKED,
}

_SEVERITY_CHOICES: dict[str, Severity] = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}

_SEVERITY_DISPLAY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)

_DEFAULT_STORAGE_ROOT = Path(".modelguard")


_F = TypeVar("_F", bound=Callable[..., Any])


def _trust_and_cache_options(func: _F) -> _F:
    """Options shared by ``verify`` and ``policy check``."""
    func = click.option(
        "--cache-dir",
        type=click.Path(path_type=Path),
        default=None,
        help="Opt in to the local digest cache in this directory. Keep it somewhere the "
        "artifact's supplier cannot write; see docs/limitations.md.",
    )(func)
    func = click.option(
        "--trusted-fingerprint",
        "trusted_fingerprints",
        multiple=True,
        help="SHA-256 fingerprint of a trusted signer public key (repeatable). Compute one "
        "with `modelguard fingerprint KEYFILE`. Without any, the signer is NOT checked.",
    )(func)
    return func


@click.group()
@click.version_option(package_name="modelguard")
def cli() -> None:
    """ModelGuard: AI/ML model supply-chain security."""


@cli.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("--format", "output_format", type=click.Choice(["text", "json"]), default="text")
def inspect(path: Path, output_format: str) -> None:
    """Inspect an artifact and print its digest and file list."""
    try:
        digest = hash_artifact(path)
    except ModelGuardError as exc:
        _fail(exc, output_format)

    if output_format == "json":
        payload = {
            "algorithm": digest.algorithm,
            "artifact_type": digest.artifact_type,
            "digest": digest.digest,
            "file_count": len(digest.files),
        }
        click.echo(json.dumps(payload, indent=2))
    else:
        click.echo(f"Artifact type : {digest.artifact_type}")
        click.echo(f"Digest        : {digest.algorithm}:{digest.digest}")
        click.echo(f"Files         : {len(digest.files)}")
        for f in digest.files[:20]:
            click.echo(f"  {f.sha256[:12]}...  {f.path}  ({f.size} bytes)")
        if len(digest.files) > 20:
            click.echo(f"  ... and {len(digest.files) - 20} more")


@cli.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
def digest(path: Path) -> None:
    """Print only the artifact digest (script-friendly)."""
    try:
        d = hash_artifact(path)
    except ModelGuardError as exc:
        _fail(exc, "text")
    click.echo(f"{d.algorithm}:{d.digest}")


@cli.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("--output", "-o", type=click.Path(path_type=Path), required=True)
@click.option("--model-id", default=None)
@click.option("--version", "model_version", default=None)
@click.option("--license", "license_", default=None)
def manifest(
    path: Path,
    output: Path,
    model_id: str | None,
    model_version: str | None,
    license_: str | None,
) -> None:
    """Generate a canonical manifest and write it to OUTPUT."""
    try:
        meta = DeclaredMetadata(model_id=model_id, version=model_version, license=license_)
        m = build_manifest(path, meta)
    except ModelGuardError as exc:
        _fail(exc, "text")

    output.write_text(m.model_dump_json(indent=2, exclude_none=True))
    click.echo(f"Wrote manifest to {output}")
    click.echo(f"Digest: {m.algorithm}:{m.digest}")


@cli.group()
def mbom() -> None:
    """ML-BOM generation and inspection."""


@mbom.command("generate")
@click.argument("manifest_path", type=click.Path(exists=True, path_type=Path))
@click.option("--output", "-o", type=click.Path(path_type=Path), required=True)
def mbom_generate(manifest_path: Path, output: Path) -> None:
    """Generate an ML-BOM from a manifest produced by `modelguard manifest`."""
    try:
        m = Manifest.model_validate(json.loads(manifest_path.read_text()))
        bom = generate_mbom(m)
    except ModelGuardError as exc:
        _fail(exc, "text")

    output.write_text(bom.to_json())
    click.echo(f"Wrote ML-BOM to {output}")


@cli.command()
@click.option("--identity", required=True, help="Signer identity, e.g. an email address.")
@click.option(
    "--output-dir",
    type=click.Path(path_type=Path),
    default=Path("."),
    help="Directory to write the keypair into.",
)
def keygen(identity: str, output_dir: Path) -> None:
    """Generate a local Ed25519 development keypair.

    WARNING: this stores an unencrypted private key on disk and is
    intended for local development only. See docs/security/signing.md.
    """
    keypair = generate_keypair(identity)
    private_path, public_path = save_keypair(keypair, output_dir)
    click.echo(f"Private key: {private_path} (mode 0600, keep this secret)")
    click.echo(f"Public key : {public_path}")
    fingerprint = public_key_fingerprint(
        keypair.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    )
    click.echo(f"Fingerprint: {fingerprint}")


@cli.command()
@click.argument("public_key_path", type=click.Path(exists=True, path_type=Path))
def fingerprint(public_key_path: Path) -> None:
    """Print the trust fingerprint (SHA-256 of the raw key) of a public key file.

    This is the value to pass as --trusted-fingerprint. Obtain it from
    the key's owner over a channel an attacker cannot tamper with.
    """
    try:
        key = load_public_key(public_key_path)
    except ModelGuardError as exc:
        _fail(exc, "text")
    click.echo(public_key_fingerprint(key.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()))


@cli.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("--manifest", "manifest_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--mbom", "mbom_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--key", "key_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--identity", required=True)
@click.option("--output", "-o", type=click.Path(path_type=Path), required=True)
def sign(
    path: Path,
    manifest_path: Path,
    mbom_path: Path,
    key_path: Path,
    identity: str,
    output: Path,
) -> None:
    """Sign a manifest + ML-BOM pair, producing a detached signature file."""
    try:
        m = Manifest.model_validate(json.loads(manifest_path.read_text()))
        bom = MLBOM.model_validate(json.loads(mbom_path.read_text()))
        keypair = load_private_key(key_path, identity)

        # Fail closed: refuse to sign if the manifest digest does not
        # match the artifact currently on disk, rather than trusting a
        # stale manifest file.
        current = hash_artifact(path)
        if f"{current.algorithm}:{current.digest}" != f"{m.algorithm}:{m.digest}":
            raise ModelGuardError(
                "Manifest digest does not match the artifact on disk. "
                "Re-run `modelguard manifest` before signing."
            )

        envelope = sign_artifact(m, bom, keypair)
    except ModelGuardError as exc:
        _fail(exc, "text")

    output.write_text(envelope.to_json())
    click.echo(f"Wrote signature to {output}")


@cli.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("--mbom", "mbom_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--signature", "signature_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option(
    "--storage-root",
    type=click.Path(path_type=Path),
    default=None,
    help="Local registry root, to also check revocation status. Omit to skip that check.",
)
@_trust_and_cache_options
@click.option("--format", "output_format", type=click.Choice(["text", "json"]), default="text")
def verify(
    path: Path,
    mbom_path: Path,
    signature_path: Path,
    storage_root: Path | None,
    trusted_fingerprints: tuple[str, ...],
    cache_dir: Path | None,
    output_format: str,
) -> None:
    """Verify an artifact against its ML-BOM and detached signature.

    Exit code 0 if allowed, 2 if the verification was denied, 1 on an
    unexpected error (missing file, malformed input, bad configuration).
    Without --trusted-fingerprint the signer is not checked: a valid
    signature then only proves *some* key signed the artifact.
    """
    try:
        guard = ModelGuard(
            storage_root=storage_root,
            cache_dir=cache_dir,
            trusted_key_fingerprints=trusted_fingerprints or None,
        )
    except ModelGuardError as exc:
        _fail(exc, output_format)
    result = guard.verify(path, mbom_path, signature_path)

    if output_format == "json":
        payload = {
            "allowed": result.allowed,
            "artifact_digest": result.artifact_digest,
            "digest_matches": result.digest_matches,
            "signature_valid": result.signature_valid,
            "signer_trusted": result.signer_trusted,
            "mbom_valid": result.mbom_valid,
            "revoked": result.revoked,
            "revocation_checked": result.revocation_checked,
            "digest_from_cache": result.digest_from_cache,
            "reasons": list(result.reasons),
        }
        click.echo(json.dumps(payload, indent=2))
    else:
        status = "ALLOWED" if result.allowed else "DENIED"
        click.echo(f"Verification: {status}")
        click.echo(f"Digest       : {result.artifact_digest}")
        click.echo(f"Signature    : {'valid' if result.signature_valid else 'INVALID'}")
        if result.signer_trusted is None:
            click.echo("Signer       : NOT CHECKED (no --trusted-fingerprint given)")
        else:
            click.echo(f"Signer       : {'trusted' if result.signer_trusted else 'NOT TRUSTED'}")
        click.echo(f"ML-BOM       : {'matches' if result.mbom_valid else 'DOES NOT MATCH'}")
        if result.revoked:
            click.echo("Revoked      : YES")
        elif not result.revocation_checked:
            click.echo("Revocation   : NOT CHECKED (no --storage-root / model identity)")
        if result.digest_from_cache:
            click.echo("Digest source: local cache (file metadata unchanged)")
        for reason in result.reasons:
            click.echo(f"  reason: {reason}")

    sys.exit(EXIT_OK if result.allowed else EXIT_DENIED)


@cli.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--manifest",
    "manifest_path",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Manifest JSON, so the metadata-completeness scanner has declared fields to check.",
)
@click.option(
    "--mbom",
    "mbom_path",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="ML-BOM JSON, so the metadata-completeness scanner has declared fields to check.",
)
@click.option(
    "--fail-on",
    type=click.Choice(list(_SEVERITY_CHOICES)),
    default="high",
    help="Exit non-zero if any finding at or above this severity exists.",
)
@click.option("--format", "output_format", type=click.Choice(["text", "json"]), default="text")
def scan(
    path: Path,
    manifest_path: Path | None,
    mbom_path: Path | None,
    fail_on: str,
    output_format: str,
) -> None:
    """Scan an artifact for unsafe serialization, exposed secrets, and
    incomplete metadata.

    --manifest/--mbom are optional; omitting them still runs the
    unsafe-serialization and secret scanners, but the metadata-
    completeness scanner has nothing to check and reports nothing.

    Exit code 0 if every scanner ran successfully and no finding at or
    above --fail-on (default: high) exists; 2 if a scanner errored or
    such a finding exists; 1 on an unexpected error (missing file,
    malformed manifest/ML-BOM JSON).
    """
    manifest_obj: Manifest | None = None
    mbom_obj: MLBOM | None = None
    try:
        if manifest_path is not None:
            manifest_obj = Manifest.model_validate(json.loads(manifest_path.read_text()))
        if mbom_path is not None:
            mbom_obj = MLBOM.model_validate(json.loads(mbom_path.read_text()))
        report = run_scanners(path, manifest_obj, mbom_obj)
    except ModelGuardError as exc:
        _fail(exc, output_format)

    threshold = _SEVERITY_CHOICES[fail_on]
    blocking = [f for f in report.findings if f.severity.rank >= threshold.rank]

    if output_format == "json":
        payload = {
            "artifact_digest": report.artifact_digest,
            "scan_id": report.scan_id,
            "scanner_statuses": report.scanner_statuses,
            "scanner_errors": report.scanner_errors,
            "clean": report.clean,
            "findings": [_finding_to_dict(f) for f in report.findings],
        }
        click.echo(json.dumps(payload, indent=2))
    else:
        _print_scan_report_text(report)

    if not report.all_scanners_ok or blocking:
        sys.exit(EXIT_DENIED)
    sys.exit(EXIT_OK)


def _finding_to_dict(f: Finding) -> dict[str, str | None]:
    return {
        "finding_id": f.finding_id,
        "scanner": f.scanner,
        "category": f.category,
        "severity": f.severity.value,
        "confidence": f.confidence.value,
        "component": f.component,
        "message": f.message,
        "remediation": f.remediation,
        "evidence": f.evidence,
        "status": f.status,
    }


def _print_scan_report_text(report: ScanReport) -> None:
    click.echo(f"Artifact digest: {report.artifact_digest}")
    statuses = ", ".join(f"{name}={status}" for name, status in report.scanner_statuses.items())
    click.echo(f"Scanners       : {statuses}")
    for name, error in report.scanner_errors.items():
        click.echo(f"  {name} ERROR: {error}")

    if not report.findings:
        click.echo("Findings       : none")
        return

    counts = {sev: report.count(sev) for sev in _SEVERITY_DISPLAY_ORDER}
    summary = ", ".join(f"{sev.value}={n}" for sev, n in counts.items() if n)
    click.echo(f"Findings       : {len(report.findings)} ({summary})")

    ordered = sorted(report.findings, key=lambda f: -f.severity.rank)
    for f in ordered:
        click.echo(f"  [{f.severity.value:<8}] {f.scanner}: {f.component}: {f.message}")
        if f.remediation:
            click.echo(f"             remediation: {f.remediation}")


@cli.command()
@click.argument("manifest_path", type=click.Path(exists=True, path_type=Path))
@click.argument("mbom_path", type=click.Path(exists=True, path_type=Path))
@click.option("--actor", required=True, help="Identity performing the registration.")
@click.option("--storage-root", type=click.Path(path_type=Path), default=_DEFAULT_STORAGE_ROOT)
def register(manifest_path: Path, mbom_path: Path, actor: str, storage_root: Path) -> None:
    """Register a manifest + ML-BOM pair in the local registry."""
    guard = ModelGuard(storage_root=storage_root)
    try:
        m = Manifest.model_validate(json.loads(manifest_path.read_text()))
        bom = MLBOM.model_validate(json.loads(mbom_path.read_text()))
        record = guard.register(m, bom, actor=actor)
    except ModelGuardError as exc:
        _fail(exc, "text")

    click.echo(f"Registered {record.model_id}@{record.version}")
    click.echo(f"URI: {record.uri}")


@cli.command()
@click.argument("model_id")
@click.argument("version")
@click.option("--storage-root", type=click.Path(path_type=Path), default=_DEFAULT_STORAGE_ROOT)
@click.option("--format", "output_format", type=click.Choice(["text", "json"]), default="text")
def resolve(model_id: str, version: str, storage_root: Path, output_format: str) -> None:
    """Resolve a registered model_id@version to its record."""
    guard = ModelGuard(storage_root=storage_root)
    record = guard.resolve(model_id, version)

    if record is None:
        click.echo(f"Error: {model_id}@{version} is not registered", err=True)
        sys.exit(EXIT_ERROR)

    revocation = guard.is_revoked(model_id, version)
    if output_format == "json":
        payload = {
            "model_id": record.model_id,
            "version": record.version,
            "artifact_digest": record.artifact_digest,
            "uri": record.uri,
            "revoked": revocation is not None,
        }
        click.echo(json.dumps(payload, indent=2))
    else:
        click.echo(f"URI    : {record.uri}")
        click.echo(f"Digest : {record.artifact_digest}")
        click.echo(f"Revoked: {'YES - ' + revocation.reason if revocation else 'no'}")


@cli.command()
@click.argument("model_id")
@click.argument("version")
@click.option("--actor", required=True)
@click.option("--reason", required=True)
@click.option("--storage-root", type=click.Path(path_type=Path), default=_DEFAULT_STORAGE_ROOT)
def revoke(model_id: str, version: str, actor: str, reason: str, storage_root: Path) -> None:
    """Revoke a registered model version."""
    guard = ModelGuard(storage_root=storage_root)
    guard.revoke(model_id, version, actor=actor, reason=reason)
    click.echo(f"Revoked {model_id}@{version}: {reason}")


@cli.command()
@click.argument("model_id")
@click.option("--storage-root", type=click.Path(path_type=Path), default=_DEFAULT_STORAGE_ROOT)
@click.option("--format", "output_format", type=click.Choice(["text", "json"]), default="text")
def lineage(model_id: str, storage_root: Path, output_format: str) -> None:
    """Show the full ancestor lineage for MODEL_ID."""
    guard = ModelGuard(storage_root=storage_root)
    events = guard.lineage(model_id)

    if output_format == "json":
        payload = [
            {"subject": e.subject_id, "relationship": e.relationship, "object": e.object_id}
            for e in events
        ]
        click.echo(json.dumps(payload, indent=2))
    else:
        if not events:
            click.echo(f"No recorded lineage for {model_id}")
        for e in events:
            click.echo(f"{e.subject_id} --{e.relationship}--> {e.object_id}")


@cli.group()
def provenance() -> None:
    """Record and query model provenance relationships."""


@provenance.command("record")
@click.argument("subject_id")
@click.argument("relationship")
@click.argument("object_id")
@click.option("--actor", required=True)
@click.option("--storage-root", type=click.Path(path_type=Path), default=_DEFAULT_STORAGE_ROOT)
def provenance_record(
    subject_id: str, relationship: str, object_id: str, actor: str, storage_root: Path
) -> None:
    """Record SUBJECT_ID --RELATIONSHIP--> OBJECT_ID.

    RELATIONSHIP must be one of: DERIVED_FROM, TRAINED_ON,
    FINE_TUNED_FROM, MERGED_FROM, QUANTIZED_FROM, EXPORTED_FROM,
    PACKAGED_IN, SIGNED_BY, BUILT_BY, EVALUATED_BY, DEPLOYED_TO,
    REVOKED_BY.
    """
    from modelguard.provenance.models import RelationshipType

    valid = set(RelationshipType.__args__)  # type: ignore[attr-defined]
    if relationship not in valid:
        _fail(
            ModelGuardError(f"Unknown relationship {relationship!r}. Valid: {sorted(valid)}"),
            "text",
        )

    guard = ModelGuard(storage_root=storage_root)
    guard.record_provenance(subject_id, relationship, object_id, actor=actor)  # type: ignore[arg-type]
    click.echo(f"Recorded: {subject_id} --{relationship}--> {object_id}")


@cli.group()
def policy() -> None:
    """Load, validate, and evaluate policy-as-code documents."""


@policy.command("validate")
@click.argument("policy_path", type=click.Path(exists=True, path_type=Path))
def policy_validate(policy_path: Path) -> None:
    """Validate a policy YAML file's schema without evaluating it."""
    try:
        doc = load_policy_file(policy_path)
    except PolicyValidationError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(EXIT_ERROR)

    click.echo(f"Policy {doc.name!r} is valid (schema version {doc.version}).")
    enabled = [name for name, cfg in doc.rules.items() if cfg.enabled]
    click.echo(f"Enabled rules: {', '.join(enabled) if enabled else '(none)'}")


@policy.command("check")
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("--mbom", "mbom_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option(
    "--signature", "signature_path", type=click.Path(exists=True, path_type=Path), required=True
)
@click.option(
    "--policy",
    "policy_file",
    type=click.Path(exists=True, path_type=Path),
    required=True,
)
@click.option(
    "--storage-root",
    type=click.Path(path_type=Path),
    default=None,
    help="Local registry root, to also check revocation status.",
)
@_trust_and_cache_options
@click.option("--format", "output_format", type=click.Choice(["text", "json"]), default="text")
def policy_check(
    path: Path,
    mbom_path: Path,
    signature_path: Path,
    policy_file: Path,
    storage_root: Path | None,
    trusted_fingerprints: tuple[str, ...],
    cache_dir: Path | None,
    output_format: str,
) -> None:
    """Verify PATH and evaluate it against a policy document.

    Exit codes: 0 = ALLOW/ALLOW_WITH_WARNINGS, 2 = DENY,
    3 = REVIEW_REQUIRED, 4 = QUARANTINE, 5 = REVOKED, 1 = error.
    """
    try:
        guard = ModelGuard(
            storage_root=storage_root,
            cache_dir=cache_dir,
            trusted_key_fingerprints=trusted_fingerprints or None,
        )
        result = guard.check_policy(path, mbom_path, signature_path, policy_file)
    except ModelGuardError as exc:
        _fail(exc, output_format)

    if output_format == "json":
        payload = {
            "decision": result.decision.value,
            "policy_name": result.policy_name,
            "policy_version": result.policy_version,
            "subject": result.subject,
            "evaluation_id": result.evaluation_id,
            "timestamp": result.timestamp,
            "failed_rules": [
                {"rule": r.rule, "action": r.action, "message": r.message}
                for r in result.failed_rules
            ],
        }
        click.echo(json.dumps(payload, indent=2))
    else:
        click.echo(result.explain())

    sys.exit(_DECISION_EXIT_CODES[result.decision])


def _fail(exc: ModelGuardError, output_format: str) -> None:
    if output_format == "json":
        click.echo(json.dumps({"error": str(exc), "type": type(exc).__name__}), err=True)
    else:
        click.echo(f"Error: {exc}", err=True)
    sys.exit(EXIT_ERROR)


if __name__ == "__main__":
    cli()
