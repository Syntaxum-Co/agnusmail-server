"""Outbound conventional SMTP API (/v1/outbound, protocol v1 §10).

**Not end-to-end encrypted**: every response carries ``protection = "not-e2ee"`` and
clients must say so before sending. Submission needs a device-bound session; the payload
is encrypted by the client to the outbound service's key (``GET /v1/outbound/keys``).
"""

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from agnusmail.core.config import Settings
from agnusmail.core.exceptions import RateLimitedError, RedisUnavailableError
from agnusmail.core.schemas import UtcDatetime
from agnusmail.infrastructure.database.transaction import run_in_transaction
from agnusmail.modules.authentication.dependencies import DbSessionFactory, actor_context
from agnusmail.modules.authentication.device_binding import DeviceSession
from agnusmail.modules.keys.schemas import encode_material
from agnusmail.modules.messages.router import Body, Pkesk
from agnusmail.modules.outbound import service
from agnusmail.modules.outbound.models import OutboundKey, OutboundMessage, OutboundRecipient

router = APIRouter(prefix="/outbound", tags=["outbound"])

Limit = Annotated[int, Query(ge=1, le=100)]
Offset = Annotated[int, Query(ge=0, le=100_000)]
HOUR = 3600
DAY = 86400


class SentCopyIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    pkesks: list[Pkesk] = Field(min_length=1, max_length=50)
    body: Body


class OutboundIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    version: int = Field(ge=1, le=1)
    message_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    recipients: list[Annotated[str, Field(max_length=254)]] = Field(min_length=1, max_length=100)
    # PKESK (to the outbound key) || SEIPDv2 of the ready MIME message (7-bit, CRLF).
    payload: Body
    sent_copy: SentCopyIn | None = None
    # One of the account's active addresses (primary or alias); default: the primary.
    # The message's From must be this address.
    sender: Annotated[str, Field(max_length=254)] | None = None


class RecipientOut(BaseModel):
    address: str
    status: str
    smtp_code: int | None
    smtp_status: str | None
    updated_at: UtcDatetime


class OutboundOut(BaseModel):
    id: uuid.UUID
    message_id: str
    kind: str
    protection: str
    sender: str
    status: str
    attempts: int
    recipients: list[RecipientOut]
    created_at: UtcDatetime
    expires_at: UtcDatetime
    finished_at: UtcDatetime | None

    @classmethod
    def build(cls, message: OutboundMessage, recipients: list[OutboundRecipient]) -> "OutboundOut":
        return cls(
            id=message.id,
            message_id=message.client_message_id,
            kind=message.kind,
            protection=service.PROTECTION,
            sender=message.sender_address,
            status=message.status,
            attempts=message.attempts,
            recipients=[
                RecipientOut(
                    address=r.address,
                    status=r.status,
                    smtp_code=r.smtp_code,
                    smtp_status=r.smtp_status,
                    updated_at=r.updated_at,
                )
                for r in recipients
            ],
            created_at=message.created_at,
            expires_at=message.expires_at,
            finished_at=message.finished_at,
        )


class OutboundPage(BaseModel):
    items: list[OutboundOut]
    limit: int
    offset: int


class OutboundKeyOut(BaseModel):
    fingerprint: str
    encryption_fingerprint: str
    material: str  # base64 of the binary v6 certificate (device profile, spec §3.1)
    expires_at: UtcDatetime
    created_at: UtcDatetime

    @classmethod
    def from_key(cls, key: OutboundKey) -> "OutboundKeyOut":
        return cls(
            fingerprint=key.fingerprint,
            encryption_fingerprint=key.encryption_fingerprint,
            material=encode_material(key.material),
            expires_at=key.expires_at,
            created_at=key.created_at,
        )


class OutboundKeyList(BaseModel):
    protection: str
    items: list[OutboundKeyOut]


async def consume_sending_quota(request: Request, owner: uuid.UUID, recipients: int) -> None:
    """Per-account sending limits. Fail-closed: the outbound channel is
    the abuse vector, so a Redis failure refuses the submission (503)."""
    settings: Settings = request.app.state.settings
    limiter = request.app.state.rate_limiter
    try:
        allowed = await limiter.consume(
            f"outbound:messages:{owner}", 1, settings.outbound_messages_per_hour, HOUR
        ) and await limiter.consume(
            f"outbound:recipients:{owner}", recipients, settings.outbound_recipients_per_day, DAY
        )
    except Exception as exc:
        request.app.state.rate_limit_failures.report()
        raise RedisUnavailableError() from exc
    if not allowed:
        raise RateLimitedError("outbound sending limit reached")


async def per_domain_limit(request: Request, owner: uuid.UUID, recipients: list[str]) -> None:
    """Recipients per destination domain and hour (no list-bombing one provider)."""
    from collections import Counter

    from agnusmail.modules.abuse import limits
    from agnusmail.modules.outbound.recipients import domain_of

    settings: Settings = request.app.state.settings
    for domain, count in sorted(Counter(domain_of(r) for r in recipients).items()):
        await limits.consume(
            request,
            "outbound_domain",
            f"{owner}:{domain}",
            count,
            settings.outbound_per_domain_per_hour,
            limits.HOUR,
            fail_closed=True,
        )


@router.get("/keys")
async def outbound_keys(db: DbSessionFactory) -> OutboundKeyList:
    """Public certificates clients encrypt outbound messages to (newest first)."""
    now = datetime.now(UTC)
    return await run_in_transaction(
        db,
        lambda s: OutboundKeyList(
            protection=service.PROTECTION,
            items=[OutboundKeyOut.from_key(k) for k in service.current_keys(s, now)],
        ),
    )


@router.post("/messages", status_code=202)
async def submit(
    request: Request, payload: OutboundIn, session: DeviceSession, db: DbSessionFactory
) -> OutboundOut:
    settings: Settings = request.app.state.settings
    owner = uuid.UUID(session.session.user_id)
    recipients = service.parse_recipients(
        list(payload.recipients), settings.mail_domain, settings.outbound_max_recipients
    )
    await consume_sending_quota(request, owner, len(recipients))
    await per_domain_limit(request, owner, recipients)
    actor = actor_context(request, session.session)
    copy = (
        None
        if payload.sent_copy is None
        else service.SentCopy(list(payload.sent_copy.pkesks), payload.sent_copy.body)
    )
    now = datetime.now(UTC)

    def work(s: Session) -> OutboundOut:
        message = service.submit(
            s,
            actor,
            client_message_id=payload.message_id,
            recipients=recipients,
            payload=payload.payload,
            sent_copy=copy,
            max_bytes=settings.outbound_max_message_bytes,
            max_copy_bytes=settings.max_message_bytes,
            now=now,
            sender=payload.sender,
            quota=request.app.state.quota_policy,
        )
        return OutboundOut.build(message, service.recipients_of(s, message.id))

    return await run_in_transaction(db, work)


@router.get("/messages")
async def list_outbound(
    session: DeviceSession, db: DbSessionFactory, limit: Limit = 25, offset: Offset = 0
) -> OutboundPage:
    owner = uuid.UUID(session.session.user_id)

    def work(s: Session) -> OutboundPage:
        items = service.list_own(s, owner, limit=limit, offset=offset)
        return OutboundPage(
            items=[OutboundOut.build(m, service.recipients_of(s, m.id)) for m in items],
            limit=limit,
            offset=offset,
        )

    return await run_in_transaction(db, work)


@router.get("/messages/{outbound_id}")
async def read_outbound(
    outbound_id: uuid.UUID, session: DeviceSession, db: DbSessionFactory
) -> OutboundOut:
    owner = uuid.UUID(session.session.user_id)

    def work(s: Session) -> OutboundOut:
        message = service.get_own(s, owner, outbound_id)
        return OutboundOut.build(message, service.recipients_of(s, message.id))

    return await run_in_transaction(db, work)
