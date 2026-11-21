"""Object storage against a real S3 API (SeaweedFS in development and CI).

Needs ``AGNUSMAIL_TEST_S3_ENDPOINT`` (e.g. http://localhost:8333) with the dev-only
credentials of docker/seaweedfs/s3.json; skipped otherwise.
"""

import os
import secrets
import urllib.error
import urllib.request

import pytest

from agnusmail.infrastructure.object_storage import S3ObjectStorage, build_object_storage
from agnusmail.testing.fakes import make_settings

pytestmark = pytest.mark.integration

ENDPOINT = os.environ.get("AGNUSMAIL_TEST_S3_ENDPOINT")


@pytest.fixture
def storage() -> S3ObjectStorage:
    if not ENDPOINT:
        pytest.skip("AGNUSMAIL_TEST_S3_ENDPOINT not set")
    bucket = f"agnusmail-it-{secrets.token_hex(4)}"
    built = build_object_storage(
        make_settings(
            object_storage_endpoint=ENDPOINT,
            object_storage_bucket=bucket,
            object_storage_access_key="agnusmail-dev",
            object_storage_secret_key="agnusmail-dev-only-not-a-secret",
        )
    )
    assert isinstance(built, S3ObjectStorage)
    built.client.create_bucket(Bucket=bucket)
    return built


def put(url: str, data: bytes) -> int:
    request = urllib.request.Request(
        url, data=data, method="PUT", headers={"Content-Type": "application/octet-stream"}
    )
    try:
        return int(urllib.request.urlopen(request, timeout=10).status)
    except urllib.error.HTTPError as exc:
        return int(exc.code)


def test_presigned_upload_download_and_delete(storage: S3ObjectStorage) -> None:
    data = secrets.token_bytes(4096)
    key = f"att/{secrets.token_hex(8)}"
    assert put(storage.presign_upload(key, len(data), 300), data) == 200
    assert storage.object_size(key) == len(data)
    with urllib.request.urlopen(storage.presign_download(key, 60), timeout=10) as response:
        assert response.read() == data
    storage.delete(key)
    assert storage.object_size(key) is None
    storage.delete(key)  # deleting a missing object is a no-op


def test_signed_size_cannot_be_exceeded(storage: S3ObjectStorage) -> None:
    key = f"att/{secrets.token_hex(8)}"
    url = storage.presign_upload(key, 100, 300)
    assert put(url, b"x" * 101) != 200  # the length is part of the signature
    assert storage.object_size(key) is None


def test_download_urls_are_bound_to_one_object(storage: S3ObjectStorage) -> None:
    key = f"att/{secrets.token_hex(8)}"
    put(storage.presign_upload(key, 3, 300), b"abc")
    url = storage.presign_download(key, 60)
    other = url.replace(key, f"att/{secrets.token_hex(8)}")
    with pytest.raises(urllib.error.HTTPError):
        urllib.request.urlopen(other, timeout=10)
