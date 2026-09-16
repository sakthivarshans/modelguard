"""ModelGuard command-line interface.

Implements the Phase 1 slice of the CLI surface described in the
architecture document: inspect, hash, manifest, mbom generate, keygen,
sign, and verify. Every command supports ``--format json`` for CI use
and returns a non-zero exit code on failure.
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
from modelguard.sdk import ModelGuard
from modelguard.signing.keys import generate_keypair, load_private_key, save_keypair
from modelguard.signing.signer import sign_artifact

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_DENIED = 2


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
@click.option("--format", "output_format", type=click.Choice(["text", "json"]), default="text")
def verify(path: Path, mbom_path: Path, signature_path: Path, output_format: str) -> None:
    """Verify an artifact against its ML-BOM and detached signature.

    Exit code 0 if allowed, 2 if the verification was denied, 1 on an
    unexpected error (missing file, malformed input).
    """
    guard = ModelGuard()
    result = guard.verify(path, mbom_path, signature_path)

    if output_format == "json":
        payload = {
            "allowed": result.allowed,
            "artifact_digest": result.artifact_digest,
            "signature_valid": result.signature_valid,
            "mbom_valid": result.mbom_valid,
            "reasons": list(result.reasons),
        }
        click.echo(json.dumps(payload, indent=2))
    else:
        status = "ALLOWED" if result.allowed else "DENIED"
        click.echo(f"Verification: {status}")
        click.echo(f"Digest       : {result.artifact_digest}")
        click.echo(f"Signature    : {'valid' if result.signature_valid else 'INVALID'}")
        click.echo(f"ML-BOM       : {'matches' if result.mbom_valid else 'DOES NOT MATCH'}")
        for reason in result.reasons:
            click.echo(f"  reason: {reason}")

    sys.exit(EXIT_OK if result.allowed else EXIT_DENIED)


def _fail(exc: ModelGuardError, output_format: str) -> None:
    if output_format == "json":
        click.echo(json.dumps({"error": str(exc), "type": type(exc).__name__}), err=True)
    else:
        click.echo(f"Error: {exc}", err=True)
    sys.exit(EXIT_ERROR)


if __name__ == "__main__":
    cli()
