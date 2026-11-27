"""Secure portal API (/v1/portal, protocol v1 §11).

Sender routes need a device-bound session. Recipient routes are public: the link token
is the capability, sent in the JSON body of a POST (never in a URL, so it stays out of
access logs); unknown and expired tokens look the same (404).
"""

import base64
import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from agnusmail.core.config import Settings
from agnusmail.core.exceptions import RateLimitedError
from agnusmail.core.schemas import UtcDatetime
from agnusmail.infrastructure.database.transaction import run_in_transaction
from agnusmail.modules.authentication.dependencies import (
    DbSessionFactory,
    actor_context,
    client_ip,
)
from agnusmail.modules.authentication.device_binding import DeviceSession
from agnusmail.modules.identity.models import User
from agnusmail.modules.identity.repository import normalize_address
from agnusmail.modules.keys.router import build_directory
from agnusmail.modules.keys.schemas import DirectoryOut
from agnusmail.modules.messages.router import Body, Pkesk
from agnusmail.modules.outbound.router import consume_sending_quota
from agnusmail.modules.outbound.service import parse_recipients
from agnusmail.modules.portal import service
from agnusmail.modules.portal.models import (
    MAX_VIEW_SECONDS,
    MIN_VIEW_SECONDS,
    PortalLink,
    PortalMessage,
)

router = APIRouter(prefix="/portal", tags=["portal"])

Limit = Annotated[int, Query(ge=1, le=100)]
Offset = Annotated[int, Query(ge=0, le=100_000)]
Token = Annotated[str, Field(pattern=service.TOKEN_PATTERN)]
PROTECTION = "e2ee-shared-secret"  # spec §11 classification


class PortalIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    version: int = Field(ge=1, le=1)
    message_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    recipients: list[Annotated[str, Field(max_length=254)]] = Field(min_length=1, max_length=100)
    expires_in_days: int = Field(ge=1, le=30)
    # PKESKs (sender's published keys) + one SKESK v6/Argon2 + SEIPDv2 (spec §11).
    envelope: Body
    notify: bool = True  # e-mail each recipient a notice with the link (not the password)
    # View once: each link is readable for this long after its first access, then never
    # again; no replies. Null: readable until expiry.
    view_seconds: int | None = Field(default=None, ge=MIN_VIEW_SECONDS, le=MAX_VIEW_SECONDS)


class LinkOut(BaseModel):
    recipient: str
    url: str


class RecipientStateOut(BaseModel):
    recipient: str
    replies: int
    last_access_at: UtcDatetime | None
    viewable_until: UtcDatetime | None  # view once: end of this link's window, once opened


class PortalOut(BaseModel):
    id: uuid.UUID
    message_id: str
    protection: str
    size: int
    recipients: list[RecipientStateOut]
    view_seconds: int | None
    expires_at: UtcDatetime
    created_at: UtcDatetime

    @classmethod
    def build(cls, message: PortalMessage, links: list[PortalLink]) -> "PortalOut":
        return cls(
            id=message.id,
            message_id=message.client_message_id,
            protection=PROTECTION,
            size=message.size,
            recipients=[
                RecipientStateOut(
                    recipient=link.recipient,
                    replies=link.replies,
                    last_access_at=link.last_access_at,
                    viewable_until=link.viewable_until,
                )
                for link in links
            ],
            view_seconds=message.view_seconds,
            expires_at=message.expires_at,
            created_at=message.created_at,
        )


class CreatedOut(PortalOut):
    links: list[LinkOut]  # shown only now: the tokens are not stored


class PortalWithEnvelopeOut(PortalOut):
    envelope: str


class PortalPage(BaseModel):
    items: list[PortalOut]
    limit: int
    offset: int


class TokenIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    token: Token


class LinkStateOut(BaseModel):  # what a link shows before the envelope
    version: int
    protection: str
    sender: str  # the sender's Agnusmail address
    # The address this link was made for: a reply's From (the server does not attest who
    # replied, only which link was used).
    recipient: str
    expires_at: UtcDatetime
    replies_left: int
    view_seconds: int | None  # view once: the window the first access opens
    viewable_until: UtcDatetime | None  # view once: set once the window is open


class AccessOut(LinkStateOut):
    envelope: str


class ReplyIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    token: Token
    version: int = Field(ge=1, le=1)
    # Encrypted in the browser to every key the portal's directory lists (spec §6.5).
    pkesks: list[Pkesk] = Field(min_length=1, max_length=50)
    body: Body


class ReplyOut(BaseModel):
    replies_left: int


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


async def _per_ip(request: Request, name: str, limit: int, window: int) -> None:
    """Unauthenticated routes: per client IP, fail-open like the global IP limit."""
    try:
        allowed = await request.app.state.rate_limiter.check(
            f"portal:{name}:{client_ip(request)}", limit, window
        )
    except Exception:
        request.app.state.rate_limit_failures.report()
        return
    if not allowed:
        raise RateLimitedError()


def _base_url(settings: Settings) -> str:
    if not settings.portal_base_url:
        raise service.PortalUnavailableError()
    return settings.portal_base_url


@router.post("/messages", status_code=201)
async def create(
    request: Request, payload: PortalIn, session: DeviceSession, db: DbSessionFactory
) -> CreatedOut:
    settings: Settings = request.app.state.settings
    base_url = _base_url(settings)
    owner = uuid.UUID(session.session.user_id)
    recipients = parse_recipients(
        list(payload.recipients), settings.mail_domain, settings.portal_max_recipients
    )
    if payload.expires_in_days > settings.portal_max_days:
        raise service.PortalExpiryInvalidError(
            f"expires_in_days must be at most {settings.portal_max_days}"
        )
    if payload.notify:  # the notices go out through the outbound channel and its limits
        await consume_sending_quota(request, owner, len(recipients))
    actor = actor_context(request, session.session)
    now = datetime.now(UTC)

    def work(s: Session) -> CreatedOut:
        created = service.create(
            s,
            actor,
            client_message_id=payload.message_id,
            recipients=recipients,
            envelope=payload.envelope,
            days=payload.expires_in_days,
            notify=payload.notify,
            base_url=base_url,
            max_bytes=settings.portal_max_message_bytes,
            max_notice_bytes=settings.outbound_max_message_bytes,
            now=now,
            quota=request.app.state.quota_policy,
            view_seconds=payload.view_seconds,
        )
        base = PortalOut.build(created.message, service.links_of(s, created.message.id))
        return CreatedOut(
            **base.model_dump(),
            links=[LinkOut(recipient=link.recipient, url=link.url) for link in created.links],
        )

    return await run_in_transaction(db, work)


@router.get("/messages")
async def list_portal(
    session: DeviceSession, db: DbSessionFactory, limit: Limit = 25, offset: Offset = 0
) -> PortalPage:
    owner = uuid.UUID(session.session.user_id)

    def work(s: Session) -> PortalPage:
        items = service.list_own(s, owner, limit=limit, offset=offset)
        return PortalPage(
            items=[PortalOut.build(m, service.links_of(s, m.id)) for m in items],
            limit=limit,
            offset=offset,
        )

    return await run_in_transaction(db, work)


@router.get("/messages/{portal_id}")
async def read_portal(
    portal_id: uuid.UUID, session: DeviceSession, db: DbSessionFactory
) -> PortalWithEnvelopeOut:
    """The sender's own copy: the envelope has PKESKs for their devices (spec §11)."""
    owner = uuid.UUID(session.session.user_id)

    def work(s: Session) -> PortalWithEnvelopeOut:
        message = service.get_own(s, owner, portal_id)
        base = PortalOut.build(message, service.links_of(s, message.id))
        return PortalWithEnvelopeOut(**base.model_dump(), envelope=_b64(message.envelope))

    return await run_in_transaction(db, work)


@router.delete("/messages/{portal_id}", status_code=204)
async def delete_portal(
    request: Request, portal_id: uuid.UUID, session: DeviceSession, db: DbSessionFactory
) -> None:
    actor = actor_context(request, session.session)
    now = datetime.now(UTC)
    await run_in_transaction(db, lambda s: service.delete_own(s, actor, portal_id, now))


def _link_out(opened: service.Opened, settings: Settings) -> LinkStateOut:
    view_once = opened.message.view_seconds is not None
    left = settings.portal_max_replies_per_link - opened.link.replies
    return LinkStateOut(
        version=1,
        protection=PROTECTION,
        sender=opened.sender,
        recipient=opened.link.recipient,
        expires_at=opened.message.expires_at,
        replies_left=0 if view_once else max(left, 0),
        view_seconds=opened.message.view_seconds,
        viewable_until=opened.link.viewable_until,
    )


@router.post("/link")
async def link(request: Request, payload: TokenIn, db: DbSessionFactory) -> LinkStateOut:
    """The link's details without the envelope: never starts a view-once window."""
    settings: Settings = request.app.state.settings
    _base_url(settings)
    await _per_ip(request, "access", settings.portal_access_per_ip_per_minute, 60)
    now = datetime.now(UTC)
    return await run_in_transaction(
        db, lambda s: _link_out(service.peek(s, payload.token, now), settings)
    )


@router.post("/access")
async def access(request: Request, payload: TokenIn, db: DbSessionFactory) -> AccessOut:
    """The envelope. For a view-once message, the first call opens this link's window."""
    settings: Settings = request.app.state.settings
    _base_url(settings)
    await _per_ip(request, "access", settings.portal_access_per_ip_per_minute, 60)
    now = datetime.now(UTC)

    def work(s: Session) -> AccessOut:
        opened = service.access(s, payload.token, now)
        return AccessOut(
            **_link_out(opened, settings).model_dump(), envelope=_b64(opened.message.envelope)
        )

    return await run_in_transaction(db, work)


@router.post("/keys")
async def sender_keys(request: Request, payload: TokenIn, db: DbSessionFactory) -> DirectoryOut:
    """The sender's directory entry, to encrypt a reply and verify it with EIP-712."""
    settings: Settings = request.app.state.settings
    _base_url(settings)
    await _per_ip(request, "access", settings.portal_access_per_ip_per_minute, 60)
    now = datetime.now(UTC)

    def work(s: Session) -> DirectoryOut:
        sender = s.get(User, service.sender_of(s, payload.token, now))
        assert sender is not None
        return build_directory(s, settings, normalize_address(sender.ethereum_address), now)

    return await run_in_transaction(db, work)


@router.post("/replies", status_code=201)
async def reply(request: Request, payload: ReplyIn, db: DbSessionFactory) -> ReplyOut:
    settings: Settings = request.app.state.settings
    _base_url(settings)
    await _per_ip(request, "replies", settings.portal_replies_per_ip_per_hour, 3600)
    now = datetime.now(UTC)
    limit = settings.portal_max_replies_per_link

    def work(s: Session) -> ReplyOut:
        replies = service.reply(
            s,
            payload.token,
            pkesks=list(payload.pkesks),
            body=payload.body,
            max_bytes=settings.max_message_bytes,
            max_replies=limit,
            now=now,
            quota=request.app.state.quota_policy,
        )
        return ReplyOut(replies_left=max(limit - replies, 0))

    return await run_in_transaction(db, work)
