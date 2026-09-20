"""S3 endpoint policy, key layout, and error translation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("botocore")
from botocore.exceptions import ClientError, EndpointConnectionError

from modelguard.storage import (
    ArtifactNotFoundError,
    ArtifactStoreError,
    StoreConfigurationError,
)
from modelguard.storage.s3 import S3BlobStore

SHA = "a" * 64


@pytest.fixture(autouse=True)
def _aws_env(s3_env: None) -> None:
    return None


@pytest.mark.parametrize(
    "url",
    ["http://s3.example.com", "http://10.0.0.5:9000", "ftp://s3.example.com", "https://", "not a url"],
)
def test_insecure_or_malformed_endpoints_are_refused(url: str) -> None:
    with pytest.raises(StoreConfigurationError):
        S3BlobStore("b", endpoint_url=url)


def test_credentials_in_the_endpoint_url_are_refused() -> None:
    with pytest.raises(StoreConfigurationError, match="Credentials"):
        S3BlobStore("b", endpoint_url="https://AKIA:secret@s3.example.com")


@pytest.mark.parametrize("url", ["https://s3.example.com", "http://localhost:9000", "http://127.0.0.1:9000"])
def test_https_and_loopback_endpoints_are_accepted(url: str) -> None:
    S3BlobStore("b", endpoint_url=url)


def test_insecure_remote_endpoint_requires_explicit_opt_in() -> None:
    S3BlobStore("b", endpoint_url="http://10.0.0.5:9000", allow_insecure_transport=True)


@pytest.mark.parametrize("prefix", ["/abs", "a/../b", "./x", "a\\b", "a\x00b"])
def test_unsafe_prefixes_are_refused(prefix: str) -> None:
    with pytest.raises(StoreConfigurationError):
        S3BlobStore("b", prefix=prefix, endpoint_url="http://localhost:9")


def test_empty_bucket_is_refused() -> None:
    with pytest.raises(StoreConfigurationError):
        S3BlobStore("")


def test_key_layout_is_content_addressed_under_the_prefix() -> None:
    store = S3BlobStore("b", prefix="team/models", endpoint_url="http://localhost:9")
    assert store._key(SHA) == f"team/models/blobs/sha256/aa/{SHA}"


def test_repr_shows_no_endpoint_or_credentials() -> None:
    text = repr(S3BlobStore("b", endpoint_url="https://s3.internal.example.com"))
    assert "internal" not in text and "testing" not in text


class _StubClient:
    """Stands in for boto3 only to force provider errors moto can't produce."""

    def __init__(self, error: Exception) -> None:
        self._error = error

    def head_object(self, **_: Any) -> None:
        raise self._error

    def head_bucket(self, **_: Any) -> dict[str, Any]:
        return {}  # the bucket exists; only the key is missing


def _client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "provider text with SECRET-DETAIL"}}, "HeadObject")


def test_permission_denied_is_an_error_not_absence() -> None:
    store = S3BlobStore("b", client=_StubClient(_client_error("403")))
    with pytest.raises(ArtifactStoreError, match="permission denied") as exc:
        store.exists(SHA)
    assert not isinstance(exc.value, ArtifactNotFoundError)
    assert "SECRET-DETAIL" not in str(exc.value)


@pytest.mark.parametrize("code", ["404", "NoSuchKey", "NotFound"])
def test_not_found_codes_mean_absent(code: str) -> None:
    assert S3BlobStore("b", client=_StubClient(_client_error(code))).exists(SHA) is False


def test_connection_failure_is_an_error_not_absence() -> None:
    err = EndpointConnectionError(endpoint_url="https://very-secret-host.example.com")
    store = S3BlobStore("b", client=_StubClient(err))
    with pytest.raises(ArtifactStoreError, match="could not connect") as exc:
        store.exists(SHA)
    assert "very-secret-host" not in str(exc.value)


def test_missing_bucket_reports_without_leaking_the_endpoint(moto_endpoint: str, tmp_path: Path) -> None:
    store = S3BlobStore("mg-no-such-bucket-xyz", endpoint_url=moto_endpoint, region_name="us-east-1")
    with pytest.raises(ArtifactStoreError, match="bucket not found") as exc:
        store.get_to(SHA, tmp_path / "o", max_bytes=10)
    assert moto_endpoint not in str(exc.value)


def test_exists_on_a_missing_bucket_is_an_error_not_an_empty_store(moto_endpoint: str) -> None:
    store = S3BlobStore("mg-no-such-bucket-abc", endpoint_url=moto_endpoint, region_name="us-east-1")
    with pytest.raises(ArtifactStoreError, match="bucket not found"):
        store.exists(SHA)


def test_bucket_is_only_probed_once_per_instance(moto_endpoint: str) -> None:
    import boto3

    raw = boto3.client("s3", endpoint_url=moto_endpoint, region_name="us-east-1")
    raw.create_bucket(Bucket="mg-probe-once")
    calls = {"n": 0}

    class Counting:
        def __getattr__(self, name: str) -> Any:
            attr = getattr(raw, name)
            if name != "head_bucket":
                return attr

            def wrapped(**kw: Any) -> Any:
                calls["n"] += 1
                return attr(**kw)

            return wrapped

    store = S3BlobStore("mg-probe-once", client=Counting())
    for i in range(5):
        assert store.exists(f"{i:064x}") is False
    assert calls["n"] == 1
