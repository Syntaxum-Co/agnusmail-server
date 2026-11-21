"""Message API (/v1/messages, protocol v1 §6). Every route needs a device-bound session
(spec §5): the caller reads with the PKESKs of the device its session is bound to."""

import base64
import binascii
import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field
from sqlalchemy.orm import Session

from agnusmail.core.config import Settings
from agnusmail.core.logging import get_logger
from agnusmail.core.schemas import UtcDatetime
from agnusmail.infrastructure.database.transaction import run_in_transaction
from agnusmail.infrastructure.metrics import MESSAGES_SENT
from agnusmail.modules.attachments.service import AttachmentLimits
from agnusmail.modules.authentication.dependencies import DbSessionFactory
from agnusmail.modules.authentication.device_binding import DeviceSession
from agnusmail.modules.messages import service
from agnusmail.modules.messages.models import Folder, MailboxEntry

router = APIRouter(prefix="/messages", tags=["messages"])
log = get_logger(__name__)

Limit = Annotated[int, Query(ge=1, le=100)]
Offset = Annotated[int, Query(ge=0, le=100_000)]
MAX_PKESK_BYTES = 4096


def _decode(value: object, *, max_bytes: int) -> bytes:
    if not isinstance(value, str):
        raise ValueError("must be a base64 string")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("invalid base64") from exc
    if not 0 < len(decoded) <= max_bytes:
        raise ValueError(f"must decode to 1..{max_bytes} bytes")
    return decoded


Pkesk = Annotated[bytes, BeforeValidator(lambda v: _decode(v, max_bytes=MAX_PKESK_BYTES))]
# Bounded again by ``max_message_bytes`` in the service; the request body limit applies too.
Body = Annotated[bytes, BeforeValidator(lambda v: _decode(v, max_bytes=16 * 1024 * 1024))]


class RecipientIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    account: str = Field(pattern=r"^0x[0-9a-fA-F]{40}$")
    pkesks: list[Pkesk] = Field(min_length=1, max_length=50)


class MessageIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    version: int = Field(ge=1, le=1)  # protocol version: only 1 is accepted
    message_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    recipients: list[RecipientIn] = Field(min_length=1, max_length=100)
    self_pkesks: list[Pkesk] = Field(min_length=1, max_length=50)
    body: Body
    # Encrypted attachments uploaded before; their references (name, key,
    # digest) are inside the encrypted body. Only the ids are visible to the server.
    attachments: list[Annotated[uuid.UUID, Field(strict=False)]] = Field(
        default_factory=list, max_length=100
    )


class SentOut(BaseModel):
    id: uuid.UUID
    message_id: str
    size: int
    created_at: UtcDatetime


class MailboxItemOut(BaseModel):
    id: uuid.UUID
    message_id: str
    # "external": received from outside and encrypted on arrival by the gateway (spec §9);
    # the client must say it was not E2EE from the origin. ``sender`` is then null.
    origin: str
    sender: str | None
    folder: str
    folder_id: uuid.UUID | None  # set when ``folder`` is "custom"
    size: int
    read: bool
    created_at: UtcDatetime

    @classmethod
    def from_item(cls, item: service.MailboxItem) -> "MailboxItemOut":
        return cls(
            id=item.message.id,
            message_id=item.message.client_message_id,
            origin=item.message.origin,
            sender=item.sender_address,
            folder=item.entry.folder,
            folder_id=item.entry.folder_id,
            size=item.message.size,
            read=item.entry.read_at is not None,
            created_at=item.message.created_at,
        )


class MailboxPage(BaseModel):
    items: list[MailboxItemOut]
    total: int
    limit: int
    offset: int


class MessageOut(MailboxItemOut):
    """The ciphertext for the session's device: an OpenPGP message is ``PKESK || body``.
    ``pkesks`` is empty when the message was not shared with this device yet (§6.4)."""

    version: int
    body: str
    pkesks: list[str]
    recovery_pkesks: list[str]


class MoveIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    folder: Folder = Field(strict=False)
    folder_id: uuid.UUID | None = Field(default=None, strict=False)  # for "custom"


class ShareIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    pkesks: list[Pkesk] = Field(min_length=1, max_length=50)


class ShareOut(BaseModel):
    added: int


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _entry_state(entry: MailboxEntry) -> dict[str, object]:
    return {
        "folder": entry.folder,
        "folder_id": None if entry.folder_id is None else str(entry.folder_id),
        "read": entry.read_at is not None,
    }


async def internal_limits(
    request: Request, db: DbSessionFactory, sender: uuid.UUID, recipients: int, now: datetime
) -> None:
    """Per-account limits on internal mail; a restricted account gets a small
    daily allowance. Metadata only (counts), never content."""
    from agnusmail.modules.abuse import limits
    from agnusmail.modules.abuse.service import restriction

    settings: Settings = request.app.state.settings
    restricted = await run_in_transaction(db, lambda s: restriction(s, sender, now) is not None)
    subject = str(sender)
    if restricted:
        await limits.consume(
            request,
            "restricted_messages",
            subject,
            1,
            settings.abuse_restricted_messages_per_day,
            limits.DAY,
            fail_closed=True,
        )
    await limits.consume(
        request, "internal_messages", subject, 1, settings.internal_messages_per_hour, limits.HOUR
    )
    await limits.consume(
        request,
        "internal_recipients",
        subject,
        recipients,
        settings.internal_recipients_per_day,
        limits.DAY,
    )


@router.post("", status_code=201)
async def send(
    request: Request, payload: MessageIn, session: DeviceSession, db: DbSessionFactory
) -> SentOut:
    settings: Settings = request.app.state.settings
    limits = service.MessageLimits(
        max_bytes=settings.max_message_bytes, max_recipients=settings.max_message_recipients
    )
    sender = uuid.UUID(session.session.user_id)
    recipients = [service.RecipientInput(r.account, list(r.pkesks)) for r in payload.recipients]
    now = datetime.now(UTC)
    await internal_limits(request, db, sender, len(recipients), now)

    def work(s: Session) -> SentOut:
        message = service.send_message(
            s,
            sender,
            payload.message_id,
            recipients,
            list(payload.self_pkesks),
            payload.body,
            limits,
            now,
            attachment_ids=list(payload.attachments),
            attachment_limits=AttachmentLimits(
                max_bytes=settings.max_attachment_bytes,
                max_per_message=settings.max_attachments_per_message,
            ),
            quota=request.app.state.quota_policy,
        )
        MESSAGES_SENT.inc()
        return SentOut(
            id=message.id,
            message_id=message.client_message_id,
            size=message.size,
            created_at=message.created_at,
        )

    return await run_in_transaction(db, work)


@router.get("")
async def list_messages(
    session: DeviceSession,
    db: DbSessionFactory,
    folder: Folder = Folder.INBOX,
    folder_id: uuid.UUID | None = None,
    limit: Limit = 25,
    offset: Offset = 0,
) -> MailboxPage:
    owner = uuid.UUID(session.session.user_id)

    def work(s: Session) -> MailboxPage:
        items, total = service.list_folder(
            s, owner, folder, limit=limit, offset=offset, folder_id=folder_id
        )
        return MailboxPage(
            items=[MailboxItemOut.from_item(i) for i in items],
            total=total,
            limit=limit,
            offset=offset,
        )

    return await run_in_transaction(db, work)


@router.get("/{message_id}")
async def read(message_id: uuid.UUID, session: DeviceSession, db: DbSessionFactory) -> MessageOut:
    owner = uuid.UUID(session.session.user_id)

    def work(s: Session) -> MessageOut:
        found = service.read_message(s, owner, session.device_id, message_id)
        base = MailboxItemOut.from_item(found.item)
        return MessageOut(
            **base.model_dump(),
            version=1,
            body=_b64(found.item.message.body),
            pkesks=[_b64(p) for p in found.pkesks],
            recovery_pkesks=[_b64(p) for p in found.recovery_pkesks],
        )

    return await run_in_transaction(db, work)


@router.post("/{message_id}/move")
async def move(
    message_id: uuid.UUID, payload: MoveIn, session: DeviceSession, db: DbSessionFactory
) -> dict[str, object]:
    owner = uuid.UUID(session.session.user_id)
    return await run_in_transaction(
        db,
        lambda s: _entry_state(
            service.move(s, owner, message_id, payload.folder, payload.folder_id)
        ),
    )


@router.delete("/{message_id}", status_code=204)
async def delete_message(
    request: Request, message_id: uuid.UUID, session: DeviceSession, db: DbSessionFactory
) -> None:
    """Permanently delete a message from the trash (frees storage)."""
    owner = uuid.UUID(session.session.user_id)
    objects = await run_in_transaction(
        db, lambda s: service.delete_permanently(s, owner, message_id)
    )
    storage = request.app.state.object_storage
    for key in objects:  # after the commit; a failure leaves an unreferenced object only
        try:
            storage.delete(key)
        except Exception:
            log.warning("attachment_object_delete_failed")


@router.post("/{message_id}/read")
async def mark_read(
    message_id: uuid.UUID, session: DeviceSession, db: DbSessionFactory
) -> dict[str, object]:
    owner = uuid.UUID(session.session.user_id)
    now = datetime.now(UTC)
    return await run_in_transaction(
        db, lambda s: _entry_state(service.mark_read(s, owner, message_id, now))
    )


@router.post("/{message_id}/keys")
async def share(
    message_id: uuid.UUID, payload: ShareIn, session: DeviceSession, db: DbSessionFactory
) -> ShareOut:
    """§6.4: give another of your devices access to this message (new PKESK only)."""
    owner = uuid.UUID(session.session.user_id)
    now = datetime.now(UTC)
    return await run_in_transaction(
        db,
        lambda s: ShareOut(
            added=service.share_with_devices(s, owner, message_id, list(payload.pkesks), now)
        ),
    )
