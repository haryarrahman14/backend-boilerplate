"""S3-compatible object storage (Cloudflare R2 in production, MinIO locally). Always path-style.

boto3 is blocking, so every network call runs in a worker thread; presigning is local and stays inline.
"""

import asyncio

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from app.platform.config import Settings


class Storage:
    def __init__(self, settings: Settings):
        self.bucket = settings.s3_bucket
        self.client = boto3.client(
            "s3",
            endpoint_url=settings.s3_endpoint,
            region_name=settings.s3_region,
            aws_access_key_id=settings.s3_access_key_id,
            aws_secret_access_key=settings.s3_secret_access_key.get_secret_value(),
            config=Config(
                signature_version="s3v4",
                s3={"addressing_style": "path"},
                connect_timeout=5,
                read_timeout=15,
                retries={"max_attempts": 3, "mode": "standard"},
                # R2 rejects the newer default CRC checksums on presigned PUTs; only send them when required.
                request_checksum_calculation="when_required",
                response_checksum_validation="when_required",
            ),
        )

    def presign_put(self, key: str, content_type: str, size: int, expires_in: int) -> str:
        """Signs Content-Type and Content-Length: the bucket rejects any other type or any other byte count,
        also when the URL is replayed after `complete`."""
        return self.client.generate_presigned_url(
            "put_object",
            Params={"Bucket": self.bucket, "Key": key, "ContentType": content_type, "ContentLength": size},
            ExpiresIn=expires_in,
        )

    def presign_get(self, key: str, expires_in: int) -> str:
        """`attachment`: the bucket origin never renders an uploaded file inline (stored XSS via HTML/SVG/PDF)."""
        return self.client.generate_presigned_url(
            "get_object",
            Params={"Bucket": self.bucket, "Key": key, "ResponseContentDisposition": "attachment"},
            ExpiresIn=expires_in,
        )

    async def object_size(self, key: str) -> int | None:
        """Size in bytes, or None when the object does not exist."""
        try:
            head = await asyncio.to_thread(self.client.head_object, Bucket=self.bucket, Key=key)
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") in ("404", "NoSuchKey", "NotFound"):
                return None
            raise
        return int(head["ContentLength"])

    async def delete(self, key: str) -> None:
        await asyncio.to_thread(self.client.delete_object, Bucket=self.bucket, Key=key)  # idempotent
