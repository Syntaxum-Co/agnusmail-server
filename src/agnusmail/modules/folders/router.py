"""User folders API (/v1/folders). Device-bound session required.

``name`` is the base64 of an OpenPGP message (PKESKs for every published key of the
account + SEIPDv2) that the client encrypted; the server never reads it. To give a new
device the names, another device re-encrypts each one with ``PUT``.
"""

import base64
import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter
from pydantic import BaseModel, BeforeValidator, ConfigDict
from sqlalchemy.orm import Session

from agnusmail.core.schemas import UtcDatetime
from agnusmail.infrastructure.database.transaction import run_in_transaction
from agnusmail.modules.authentication.dependencies import DbSessionFactory
from agnusmail.modules.authentication.device_binding import DeviceSession
from agnusmail.modules.folders import service
from agnusmail.modules.folders.models import MAX_NAME_BYTES, MailFolder
from agnusmail.modules.messages.router import _decode

router = APIRouter(prefix="/folders", tags=["folders"])

Name = Annotated[bytes, BeforeValidator(lambda v: _decode(v, max_bytes=MAX_NAME_BYTES))]


class FolderIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    name: Name


class FolderOut(BaseModel):
    id: uuid.UUID
    name: str
    messages: int
    unread: int
    created_at: UtcDatetime
    updated_at: UtcDatetime

    @classmethod
    def build(cls, folder: MailFolder, messages: int = 0, unread: int = 0) -> "FolderOut":
        return cls(
            id=folder.id,
            name=base64.b64encode(folder.name).decode("ascii"),
            messages=messages,
            unread=unread,
            created_at=folder.created_at,
            updated_at=folder.updated_at,
        )


class FolderList(BaseModel):
    items: list[FolderOut]


class DeletedOut(BaseModel):
    returned: int  # messages sent back to inbox/sent


@router.post("", status_code=201)
async def create_folder(
    payload: FolderIn, session: DeviceSession, db: DbSessionFactory
) -> FolderOut:
    owner = uuid.UUID(session.session.user_id)
    now = datetime.now(UTC)
    return await run_in_transaction(
        db, lambda s: FolderOut.build(service.create(s, owner, payload.name, now))
    )


@router.get("")
async def list_folders(session: DeviceSession, db: DbSessionFactory) -> FolderList:
    owner = uuid.UUID(session.session.user_id)

    def work(s: Session) -> FolderList:
        rows = service.list_folders(s, owner)
        return FolderList(items=[FolderOut.build(f, n, u) for f, n, u in rows])

    return await run_in_transaction(db, work)


@router.put("/{folder_id}")
async def rename_folder(
    folder_id: uuid.UUID, payload: FolderIn, session: DeviceSession, db: DbSessionFactory
) -> FolderOut:
    owner = uuid.UUID(session.session.user_id)
    now = datetime.now(UTC)
    return await run_in_transaction(
        db, lambda s: FolderOut.build(service.rename(s, owner, folder_id, payload.name, now))
    )


@router.delete("/{folder_id}")
async def delete_folder(
    folder_id: uuid.UUID, session: DeviceSession, db: DbSessionFactory
) -> DeletedOut:
    owner = uuid.UUID(session.session.user_id)
    return await run_in_transaction(
        db, lambda s: DeletedOut(returned=service.delete(s, owner, folder_id))
    )
