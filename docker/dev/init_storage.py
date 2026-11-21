"""Development only: create the attachments bucket and allow the web app's origins
(browsers upload/download attachments straight to the storage with presigned URLs)."""

import os
import time

from agnusmail.core.config import get_settings
from agnusmail.infrastructure.object_storage import S3ObjectStorage, build_object_storage

settings = get_settings()
storage = build_object_storage(settings)
assert isinstance(storage, S3ObjectStorage), "object storage is not configured"
origins = [o.strip() for o in os.environ["DEV_FRONTEND_ORIGINS"].split(",") if o.strip()]
for _attempt in range(60):
    try:
        names = [b["Name"] for b in storage.client.list_buckets().get("Buckets", [])]
        break
    except Exception:  # storage still starting
        time.sleep(1)
else:
    raise SystemExit("object storage did not come up")
if storage.bucket not in names:
    storage.client.create_bucket(Bucket=storage.bucket)
storage.client.put_bucket_cors(
    Bucket=storage.bucket,
    CORSConfiguration={
        "CORSRules": [
            {
                "AllowedOrigins": origins,
                "AllowedMethods": ["PUT", "GET", "HEAD"],
                "AllowedHeaders": ["*"],
                "MaxAgeSeconds": 600,
            }
        ]
    },
)
print(f"bucket {storage.bucket} ready; CORS for {origins}")
