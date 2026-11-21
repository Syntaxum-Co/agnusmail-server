"""S3-compatible object storage for encrypted attachments.

Any S3-compatible provider works; development and tests use SeaweedFS. The server
never reads attachment contents: clients upload and download ciphertext directly with
short-lived presigned URLs; the server only checks size (HEAD) and deletes orphans.
"""

from dataclasses import dataclass
from typing import Any, Protocol

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from agnusmail.core.config import Settings


class ObjectStorage(Protocol):
    def presign_upload(self, key: str, size: int, ttl_seconds: int) -> str: ...

    def presign_download(self, key: str, ttl_seconds: int) -> str: ...

    def object_size(self, key: str) -> int | None:
        """Size in bytes, or None when the object does not exist."""

    def delete(self, key: str) -> None: ...


@dataclass
class S3ObjectStorage:
    client: Any
    bucket: str

    def presign_upload(self, key: str, size: int, ttl_seconds: int) -> str:
        url: str = self.client.generate_presigned_url(
            "put_object",
            Params={
                "Bucket": self.bucket,
                "Key": key,
                "ContentLength": size,
                "ContentType": "application/octet-stream",
            },
            ExpiresIn=ttl_seconds,
        )
        return url

    def presign_download(self, key: str, ttl_seconds: int) -> str:
        url: str = self.client.generate_presigned_url(
            "get_object",
            Params={
                "Bucket": self.bucket,
                "Key": key,
                "ResponseContentType": "application/octet-stream",
                "ResponseContentDisposition": "attachment",
            },
            ExpiresIn=ttl_seconds,
        )
        return url

    def object_size(self, key: str) -> int | None:
        try:
            head = self.client.head_object(Bucket=self.bucket, Key=key)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in ("404", "NoSuchKey", "NotFound"):
                return None
            raise
        return int(head["ContentLength"])

    def delete(self, key: str) -> None:
        self.client.delete_object(Bucket=self.bucket, Key=key)


def build_object_storage(settings: Settings) -> ObjectStorage | None:
    """None when attachments are not configured (the API then answers 503)."""
    if not settings.object_storage_endpoint:
        return None
    assert settings.object_storage_access_key and settings.object_storage_secret_key
    client = boto3.client(
        "s3",
        endpoint_url=settings.object_storage_endpoint,
        region_name=settings.object_storage_region,
        aws_access_key_id=settings.object_storage_access_key,
        aws_secret_access_key=settings.object_storage_secret_key.get_secret_value(),
        config=Config(
            signature_version="s3v4",
            s3={"addressing_style": "path"},
            connect_timeout=5,
            read_timeout=10,
            retries={"max_attempts": 2},
        ),
    )
    return S3ObjectStorage(client=client, bucket=str(settings.object_storage_bucket))
