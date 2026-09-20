"""S3-compatible ``BlobStore`` (AWS S3, MinIO, and similar).

Requires the optional dependency: ``pip install "modelguard[s3]"``.

SECURITY MODEL
--------------
* **The store is untrusted; the digest is the authority.** Every read is
  streamed through SHA-256 and compared with the blob's identifier
  before anything is kept, so a tampered, swapped, or corrupted object
  is detected and refused (``ArtifactIntegrityError``), never returned.
  Integrity therefore does not depend on bucket policy, versioning, or
  the provider -- although you should still lock the bucket down for
  availability and confidentiality.
* **Credentials are never parameters.** They come from boto3's standard
  chain (environment, shared config, instance/task role) or from a
  pre-built ``client`` you inject. Nothing here logs or embeds them.
* **Transport.** A custom ``endpoint_url`` must be ``https`` unless it
  points at loopback (or ``allow_insecure_transport=True``, for tests).
  Provider TLS verification stays at boto3's default (on).
* **Errors are categories.** Provider messages and endpoints are not
  copied into exceptions. A 403 is *permission denied*, not "missing";
  outages raise rather than reading as "absent".
* **Permissions.** The store needs ``s3:GetObject``, ``s3:PutObject``
  and ``s3:ListBucket`` (so a missing key reports 404 rather than 403)
  on its prefix; it never deletes except to remove an object it just
  wrote whose content failed verification. Consider Object Lock or
  versioning for availability -- a same-digest overwrite with bad bytes
  is detected on read but would deny service until repaired.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any
from urllib.parse import urlparse

from botocore.exceptions import BotoCoreError, ClientError

from modelguard.storage._io import (
    CHUNK_SIZE,
    HashingReader,
    open_regular_nofollow,
    validate_sha256,
    write_verified,
)
from modelguard.storage.errors import (
    ArtifactIntegrityError,
    ArtifactNotFoundError,
    ArtifactStoreError,
    StoreConfigurationError,
)

_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_NOT_FOUND_CODES = frozenset({"404", "NoSuchKey", "NotFound"})


def _check_prefix(prefix: str) -> str:
    if not prefix:
        return ""
    segments = prefix.split("/")
    bad = (
        prefix.startswith("/")
        or any(s in {".", ".."} for s in segments)
        or any(ord(c) < 32 for c in prefix)
        or "\\" in prefix
    )
    if bad:
        raise StoreConfigurationError(
            "The S3 key prefix must be relative, without '.'/'..' segments, backslashes, "
            "or control characters."
        )
    return prefix if prefix.endswith("/") else prefix + "/"


def _check_endpoint(endpoint_url: str, allow_insecure_transport: bool) -> None:
    parsed = urlparse(endpoint_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise StoreConfigurationError("The S3 endpoint_url must be an http(s) URL with a host.")
    if parsed.username or parsed.password:
        raise StoreConfigurationError(
            "Credentials must not be embedded in the endpoint URL; use the standard AWS "
            "credential chain."
        )
    if (
        parsed.scheme != "https"
        and parsed.hostname not in _LOCAL_HOSTS
        and not allow_insecure_transport
    ):
        raise StoreConfigurationError(
            "Refusing a non-https S3 endpoint that is not loopback: traffic (including blob "
            "contents) would be readable and modifiable on the network path."
        )


def _translate(action: str, exc: Exception) -> ArtifactStoreError:
    """Reduce a boto error to a safe category (+ AWS error code)."""
    if isinstance(exc, ClientError):
        code = str(exc.response.get("Error", {}).get("Code", "unknown"))
        if code in _NOT_FOUND_CODES:
            return ArtifactNotFoundError("Blob not found in the object store.")
        if code in {"AccessDenied", "403", "Forbidden"}:
            return ArtifactStoreError(f"S3 {action} failed: permission denied ({code}).")
        if code == "NoSuchBucket":
            return ArtifactStoreError(f"S3 {action} failed: bucket not found ({code}).")
        return ArtifactStoreError(f"S3 {action} failed: storage error ({code}).")
    return ArtifactStoreError(
        f"S3 {action} failed: could not connect or transfer ({type(exc).__name__})."
    )


class S3BlobStore:
    """``BlobStore`` backed by an S3-compatible bucket."""

    def __init__(
        self,
        bucket: str,
        *,
        prefix: str = "",
        client: Any = None,
        endpoint_url: str | None = None,
        region_name: str | None = None,
        allow_insecure_transport: bool = False,
    ) -> None:
        if not bucket:
            raise StoreConfigurationError("A bucket name is required.")
        self._bucket = bucket
        self._prefix = _check_prefix(prefix)
        self._bucket_confirmed = False
        if client is not None:
            self._client = client
            return
        if endpoint_url is not None:
            _check_endpoint(endpoint_url, allow_insecure_transport)
        try:
            import boto3
            from botocore.config import Config
        except ImportError:  # pragma: no cover - boto3 is a hard import above via botocore
            raise StoreConfigurationError('Install the S3 extra: pip install "modelguard[s3]"') from None
        self._client = boto3.client(
            "s3",
            endpoint_url=endpoint_url,
            region_name=region_name,
            config=Config(
                connect_timeout=5,
                read_timeout=60,
                retries={"max_attempts": 3, "mode": "standard"},
            ),
        )

    def __repr__(self) -> str:
        return f"S3BlobStore(bucket={self._bucket!r}, prefix={self._prefix!r})"

    def _key(self, sha256: str) -> str:
        validate_sha256(sha256)
        return f"{self._prefix}blobs/sha256/{sha256[:2]}/{sha256}"

    def _confirm_bucket(self, action: str) -> None:
        """Called on a "not found" answer: S3 replies to HEAD with a
        bodiless 404 for a missing *bucket* too, so a misspelled bucket
        would otherwise masquerade as an empty store. Checked once per
        instance; a 403 here (no HeadBucket permission) is not evidence
        either way and is ignored."""
        if self._bucket_confirmed:
            return
        try:
            self._client.head_bucket(Bucket=self._bucket)
        except ClientError as exc:
            code = str(exc.response.get("Error", {}).get("Code", ""))
            if code in {"404", "NoSuchBucket", "NotFound"}:
                raise ArtifactStoreError(
                    f"S3 {action} failed: bucket not found ({code or '404'})."
                ) from None
        except BotoCoreError as exc:
            raise _translate(action, exc) from None
        self._bucket_confirmed = True

    def exists(self, sha256: str) -> bool:
        key = self._key(sha256)
        try:
            self._client.head_object(Bucket=self._bucket, Key=key)
        except (ClientError, BotoCoreError) as exc:
            translated = _translate("existence check", exc)
            if isinstance(translated, ArtifactNotFoundError):
                self._confirm_bucket("existence check")
                return False
            raise translated from None
        return True

    def put(self, sha256: str, source: Any) -> None:
        key = self._key(sha256)
        with open_regular_nofollow(source) as raw:
            reader = HashingReader(raw)
            try:
                self._client.upload_fileobj(reader, self._bucket, key)
            except (ClientError, BotoCoreError) as exc:
                raise _translate("upload", exc) from None
        if reader.hexdigest() != sha256:
            # We just wrote bytes that do not belong at this key. Remove
            # them (readers would reject them anyway) and refuse.
            try:
                self._client.delete_object(Bucket=self._bucket, Key=key)
            except (ClientError, BotoCoreError):
                pass
            raise ArtifactIntegrityError(
                "The source file does not hash to the claimed SHA-256 (it may have changed "
                "after hashing); the upload was discarded."
            )

    def get_to(self, sha256: str, dest: Any, *, max_bytes: int) -> None:
        key = self._key(sha256)
        try:
            head = self._client.head_object(Bucket=self._bucket, Key=key)
            declared = int(head.get("ContentLength", 0))
            if declared > max_bytes:
                raise ArtifactIntegrityError(
                    f"Blob is {declared} bytes, over the limit of {max_bytes}; download refused."
                )
            body = self._client.get_object(Bucket=self._bucket, Key=key)["Body"]
            try:
                write_verified(
                    _iter_body(body), dest, expected_sha256=sha256, max_bytes=max_bytes
                )
            finally:
                body.close()
        except (ClientError, BotoCoreError) as exc:
            translated = _translate("download", exc)
            if isinstance(translated, ArtifactNotFoundError):
                self._confirm_bucket("download")
            raise translated from None


def _iter_body(body: Any) -> Iterator[bytes]:
    yield from body.iter_chunks(CHUNK_SIZE)
