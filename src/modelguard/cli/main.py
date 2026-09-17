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
from pathlib import Path

import click

from modelguard.exceptions import ModelGuardError
from modelguard.hashing.digest import hash_artifact
from modelguard.manifest.builder import DeclaredMetadata, build_manifest
from modelguard.manifest.models import Manifest
from modelguard.mbom.generator import generate_mbom
from modelguard.mbom.models import MLBOM
from modelguard.policy.loader import PolicyValidationError, load_policy_file
from modelguard.policy.models import Decision
from modelguard.sdk import ModelGuard
from modelguard.signing.keys import generate_keypair, load_private_key, save_keypair
from modelguard.signing.signer import sign_artifact

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

_DEFAULT_STORAGE_ROOT = Path(".modelguard")


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
@click.option("--format", "output_format", type=click.Choice(["text", "json"]), default="text")
def verify(
    path: Path,
    mbom_path: Path,
    signature_path: Path,
    storage_root: Path | None,
    output_format: str,
) -> None:
    """Verify an artifact against its ML-BOM and detached signature.

    Exit code 0 if allowed, 2 if the verification was denied, 1 on an
    unexpected error (missing file, malformed input).
    """
    guard = ModelGuard(storage_root=storage_root)
    result = guard.verify(path, mbom_path, signature_path)

    if output_format == "json":
        payload = {
            "allowed": result.allowed,
            "artifact_digest": result.artifact_digest,
            "signature_valid": result.signature_valid,
            "mbom_valid": result.mbom_valid,
            "revoked": result.revoked,
            "reasons": list(result.reasons),
        }
        click.echo(json.dumps(payload, indent=2))
    else:
        status = "ALLOWED" if result.allowed else "DENIED"
        click.echo(f"Verification: {status}")
        click.echo(f"Digest       : {result.artifact_digest}")
        click.echo(f"Signature    : {'valid' if result.signature_valid else 'INVALID'}")
        click.echo(f"ML-BOM       : {'matches' if result.mbom_valid else 'DOES NOT MATCH'}")
        if result.revoked:
            click.echo("Revoked      : YES")
        for reason in result.reasons:
            click.echo(f"  reason: {reason}")

    sys.exit(EXIT_OK if result.allowed else EXIT_DENIED)


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
@click.option("--format", "output_format", type=click.Choice(["text", "json"]), default="text")
def policy_check(
    path: Path,
    mbom_path: Path,
    signature_path: Path,
    policy_file: Path,
    storage_root: Path | None,
    output_format: str,
) -> None:
    """Verify PATH and evaluate it against a policy document.

    Exit codes: 0 = ALLOW/ALLOW_WITH_WARNINGS, 2 = DENY,
    3 = REVIEW_REQUIRED, 4 = QUARANTINE, 5 = REVOKED, 1 = error.
    """
    guard = ModelGuard(storage_root=storage_root)
    try:
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
