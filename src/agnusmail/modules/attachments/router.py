"""Attachment API (/v1/attachments, protocol v1 §7). Device-bound sessions only.

1. ``POST /v1/attachments`` {size, sha256} → presigned PUT URL (ciphertext only).
2. The client uploads the SEIPDv2 object straight to the storage.
3. ``POST /v1/attachments/{id}/complete`` → the server checks the size.
4. ``POST /v1/messages`` with ``attachments: [id]`` grants the participants access.
5. ``GET /v1/attachments/{id}`` → short-lived presigned GET URL.
"""

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from agnusmail.core.config import Settings
from agnusmail.infrastructure.database.transaction import run_in_transaction
from agnusmail.infrastructure.object_storage import ObjectStorage
from agnusmail.modules.attachments import service
from agnusmail.modules.authentication.dependencies import DbSessionFactory
from agnusmail.modules.authentication.device_binding import DeviceSession

router = APIRouter(prefix="/attachments", tags=["attachments"])


class UploadIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    size: int = Field(ge=1)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class UploadOut(BaseModel):
    id: uuid.UUID
    upload_url: str
    expires_in: int
    headers: dict[str, str]


class AttachmentOut(BaseModel):
    id: uuid.UUID
    size: int
    sha256: str
    status: str


class DownloadOut(AttachmentOut):
    download_url: str
    expires_in: int


def _storage(request: Request) -> ObjectStorage:
    storage: ObjectStorage | None = request.app.state.object_storage
    if storage is None:
        raise service.AttachmentsUnavailableError()
    return storage


def _limits(settings: Settings) -> service.AttachmentLimits:
    return service.AttachmentLimits(
        max_bytes=settings.max_attachment_bytes,
        max_per_message=settings.max_attachments_per_message,
    )


@router.post("", status_code=201)
async def create_upload(
    request: Request, payload: UploadIn, session: DeviceSession, db: DbSessionFactory
) -> UploadOut:
    settings: Settings = request.app.state.settings
    storage = _storage(request)
    owner = uuid.UUID(session.session.user_id)
    attachment = await run_in_transaction(
        db,
        lambda s: service.create_upload(
            s,
            owner,
            payload.size,
            payload.sha256,
            _limits(settings),
            request.app.state.quota_policy,
        ),
    )
    ttl = settings.attachment_upload_url_ttl_seconds
    return UploadOut(
        id=attachment.id,
        upload_url=storage.presign_upload(attachment.object_key, attachment.size, ttl),
        expires_in=ttl,
        headers={"Content-Type": "application/octet-stream"},
    )


@router.post("/{attachment_id}/complete")
async def complete_upload(
    request: Request, attachment_id: uuid.UUID, session: DeviceSession, db: DbSessionFactory
) -> AttachmentOut:
    storage = _storage(request)
    owner = uuid.UUID(session.session.user_id)
    now = datetime.now(UTC)

    def work(s: Session) -> AttachmentOut:
        a = service.complete_upload(s, owner, attachment_id, storage, now)
        return AttachmentOut(id=a.id, size=a.size, sha256=a.sha256, status=a.status)

    return await run_in_transaction(db, work)


@router.get("/{attachment_id}")
async def download(
    request: Request, attachment_id: uuid.UUID, session: DeviceSession, db: DbSessionFactory
) -> DownloadOut:
    settings: Settings = request.app.state.settings
    storage = _storage(request)
    user = uuid.UUID(session.session.user_id)
    attachment = await run_in_transaction(db, lambda s: service.readable(s, user, attachment_id))
    ttl = settings.attachment_download_url_ttl_seconds
    return DownloadOut(
        id=attachment.id,
        size=attachment.size,
        sha256=attachment.sha256,
        status=attachment.status,
        download_url=storage.presign_download(attachment.object_key, ttl),
        expires_in=ttl,
    )
