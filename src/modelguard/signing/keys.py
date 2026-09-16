"""Local Ed25519 key management.

SECURITY NOTE (read before using in anything but local development):

Keys generated and loaded here are stored as raw, unencrypted Ed25519
key bytes on the local filesystem. This is sufficient for Phase 1's
goal -- proving the sign/verify pipeline works end-to-end on a single
machine -- and is explicitly *not* a production key-management story.

Production deployments must use one of the future adapters described
in the architecture document (Sigstore, KMS, HSM, hardware-backed
keys). ModelGuard will refuse to silently treat a local file key as
equivalent to those; callers must opt in explicitly and the resulting
signer identity is always labeled with its key source.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from modelguard.exceptions import InvalidKeyError, KeyNotFoundError

_PRIVATE_KEY_SUFFIX = ".modelguard.key"
_PUBLIC_KEY_SUFFIX = ".modelguard.pub"


@dataclass(frozen=True, slots=True)
class LocalKeyPair:
    """An Ed25519 keypair with a caller-chosen identity label.

    ``identity`` is an opaque string (e.g. an email address or service
    name) that ends up in the signature envelope as the signer's
    claimed identity. Phase 1 does not verify that the identity is
    "real" in any sense -- that is the job of the future Sigstore /
    enterprise-identity-provider adapter.
    """

    identity: str
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey


def generate_keypair(identity: str) -> LocalKeyPair:
    """Generate a new local Ed25519 keypair. Not persisted until
    ``save_keypair`` is called.
    """
    private_key = Ed25519PrivateKey.generate()
    return LocalKeyPair(identity=identity, private_key=private_key, public_key=private_key.public_key())


def save_keypair(keypair: LocalKeyPair, directory: Path) -> tuple[Path, Path]:
    """Persist a keypair as two files under ``directory``.

    The private key file is created with mode 0600 (owner read/write
    only) immediately at creation time -- there is no window where the
    key is world-readable on disk.

    Returns (private_key_path, public_key_path).
    """
    directory.mkdir(parents=True, exist_ok=True)
    safe_name = keypair.identity.replace("/", "_").replace("@", "_at_")

    private_path = directory / f"{safe_name}{_PRIVATE_KEY_SUFFIX}"
    public_path = directory / f"{safe_name}{_PUBLIC_KEY_SUFFIX}"

    private_bytes = keypair.private_key.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )
    public_bytes = keypair.public_key.public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )

    # Write with restrictive permissions from the start using a raw file
    # descriptor opened with mode 0o600, instead of chmod-after-write
    # which leaves a brief window where the private key is readable by
    # other local users.
    fd = os.open(str(private_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, private_bytes)
    finally:
        os.close(fd)
    private_path.chmod(stat.S_IRUSR | stat.S_IWUSR)

    public_path.write_bytes(public_bytes)

    return private_path, public_path


def load_private_key(path: Path, identity: str) -> LocalKeyPair:
    """Load a raw Ed25519 private key from disk."""
    if not path.exists():
        raise KeyNotFoundError(str(path))
    raw = path.read_bytes()
    if len(raw) != 32:
        raise InvalidKeyError(
            f"Expected a 32-byte raw Ed25519 private key at {path}, got {len(raw)} bytes"
        )
    try:
        private_key = Ed25519PrivateKey.from_private_bytes(raw)
    except Exception as exc:  # cryptography raises ValueError on malformed bytes
        raise InvalidKeyError(f"File at {path} is not a valid Ed25519 private key") from exc
    return LocalKeyPair(identity=identity, private_key=private_key, public_key=private_key.public_key())


def load_public_key(path: Path) -> Ed25519PublicKey:
    """Load a raw Ed25519 public key from disk."""
    if not path.exists():
        raise KeyNotFoundError(str(path))
    raw = path.read_bytes()
    if len(raw) != 32:
        raise InvalidKeyError(
            f"Expected a 32-byte raw Ed25519 public key at {path}, got {len(raw)} bytes"
        )
    try:
        return Ed25519PublicKey.from_public_bytes(raw)
    except Exception as exc:
        raise InvalidKeyError(f"File at {path} is not a valid Ed25519 public key") from exc
