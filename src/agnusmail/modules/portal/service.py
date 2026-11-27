"""Secure portal use cases (protocol v1 §11).

The server checks the envelope's headers (Argon2 SKESK, SEIPDv2, PKESKs for exactly the
sender's published keys) and never decrypts. Each recipient gets a link with a random
256-bit token; only its SHA-256 is stored. The optional notice is a fixed, server-built
text (sender's address, link, expiry — never the message or the password), encrypted to
the outbound queue key and sent through the conventional outbound channel.

Replies: whoever holds a link may reply, encrypted in the browser to the sender's
published keys (§6.5 completeness); the reply lands in the sender's inbox with
``origin = portal``. The server does not vouch for who wrote it.

View once (``view_seconds``): only ``access`` hands out the envelope, and its first call
for a link starts that link's window; ``peek`` shows the rest without starting it. After
the window the link is gone (404) and takes no replies at any time. When every link has
been opened, the message expires as the last window ends and the purge deletes it,
the sender's copy included. The server cannot stop a reader from keeping what they saw
during the window.
"""

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from typing import TYPE_CHECKING

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from agnusmail.core.exceptions import AgnusmailError, ConflictError, ResourceNotFoundError
from agnusmail.infrastructure.openpgp import (
    EnvelopeRejectedError,
    encrypt_to_certificates,
    portal_envelope_pkesks,
)
from agnusmail.modules.audit.models import AuditEventType
from agnusmail.modules.audit.service import ActorContext, record_event
from agnusmail.modules.messages.models import MessageOrigin
from agnusmail.modules.messages.service import (
    EnvelopeInvalidError,
    check_owner_pkesks,
    store_for_owner,
)
from agnusmail.modules.outbound.models import OutboundKind
from agnusmail.modules.outbound.service import (
    OutboundUnavailableError,
    current_keys,
    enqueue,
    reject_hosted,
    sender_address,
)
from agnusmail.modules.portal.models import PortalLink, PortalMessage
from agnusmail.modules.quotas.usage import add_usage

if TYPE_CHECKING:
    from agnusmail.modules.quotas.policy import QuotaPolicy

TOKEN_PATTERN = r"^[A-Za-z0-9_-]{43}$"  # noqa: S105  (a format, not a secret)


class PortalUnavailableError(AgnusmailError):
    status_code = 503
    message = "the secure portal is not configured"
    code = "PORTAL_UNAVAILABLE"


class PortalExpiryInvalidError(AgnusmailError):
    status_code = 422
    message = "invalid expiry"
    code = "PORTAL_EXPIRY_INVALID"


class ReplyLimitError(AgnusmailError):
    status_code = 409
    message = "no more replies are accepted for this link"
    code = "REPLY_LIMIT"


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def link_url(base_url: str, token: str) -> str:
    return f"{base_url}#{token}"


@dataclass(frozen=True)
class CreatedLink:
    recipient: str
    url: str  # contains the token: returned once, never stored


@dataclass(frozen=True)
class Created:
    message: PortalMessage
    links: list[CreatedLink]


def _minutes(seconds: int) -> str:
    minutes = max(seconds // 60, 1)
    return f"{minutes} minute{'s' if minutes != 1 else ''}"


def notice(
    sender: str,
    recipient: str,
    url: str,
    expires_at: datetime,
    view_seconds: int | None = None,
) -> bytes:
    """The notice e-mail: fixed text, 7-bit, nothing from the message itself."""
    lines = [
        f"From: {sender}",
        f"To: {recipient}",
        f"Subject: Encrypted message from {sender}",
        "MIME-Version: 1.0",
        "Content-Type: text/plain; charset=us-ascii",
        "Content-Transfer-Encoding: 7bit",
        "",
        f"{sender} sent you an end-to-end encrypted message through Agnusmail.",
        "",
        "Open it here:",
        url,
        "",
        "You need the password the sender gives you through another channel",
        "(it is never sent by e-mail).",
        f"The message will be deleted on {format_datetime(expires_at)}.",
        *(
            [
                "",
                f"It can be read only once: you have {_minutes(view_seconds)} after you open it",
                "with the password. After that the link stops working.",
            ]
            if view_seconds is not None
            else []
        ),
        "",
        "If you were not expecting it, you can ignore this e-mail.",
    ]
    return ("\r\n".join(lines) + "\r\n").encode("ascii")


def create(
    session: Session,
    actor: ActorContext,
    *,
    client_message_id: str,
    recipients: list[str],
    envelope: bytes,
    days: int,
    notify: bool,
    base_url: str,
    max_bytes: int,
    max_notice_bytes: int,
    now: datetime,
    quota: "QuotaPolicy | None" = None,
    view_seconds: int | None = None,
) -> Created:
    reject_hosted(session, recipients)
    from agnusmail.modules.abuse.service import require_unrestricted

    require_unrestricted(session, actor.user_id, now)  # abuse restriction
    if quota is not None:
        quota.require_space(session, actor.user_id, len(envelope), now)
    sender = sender_address(session, actor.user_id)
    if len(envelope) > max_bytes:
        raise EnvelopeInvalidError(f"envelope exceeds {max_bytes} bytes")
    try:
        pkesks = portal_envelope_pkesks(envelope)
    except EnvelopeRejectedError as exc:
        raise EnvelopeInvalidError(f"envelope: {exc.reason}") from exc
    check_owner_pkesks(session, actor.user_id, pkesks, now)
    duplicate = session.scalar(
        select(PortalMessage.id).where(
            PortalMessage.sender_id == actor.user_id,
            PortalMessage.client_message_id == client_message_id,
        )
    )
    if duplicate is not None:
        raise ConflictError("message_id already used by this sender")
    keys = current_keys(session, now) if notify else []
    if notify and not keys:
        raise OutboundUnavailableError()

    message = PortalMessage(
        sender_id=actor.user_id,
        client_message_id=client_message_id,
        envelope=envelope,
        size=len(envelope),
        expires_at=now + timedelta(days=days),
        view_seconds=view_seconds,
        created_at=now,
    )
    session.add(message)
    session.flush()
    add_usage(session, actor.user_id, message.size)
    links: list[CreatedLink] = []
    for recipient in recipients:
        token = secrets.token_urlsafe(32)
        session.add(
            PortalLink(
                portal_message_id=message.id,
                token_hash=token_hash(token),
                recipient=recipient,
                created_at=now,
            )
        )
        url = link_url(base_url, token)
        links.append(CreatedLink(recipient, url))
        if notify:
            text = notice(sender, recipient, url, message.expires_at, view_seconds)
            sealed = encrypt_to_certificates(text, [keys[0].material])
            payload = sealed.pkesks[keys[0].encryption_fingerprint] + sealed.body
            del text
            enqueue(
                session,
                user_id=actor.user_id,
                client_message_id=secrets.token_hex(16),
                kind=OutboundKind.PORTAL_NOTICE,
                sender=sender,
                recipients=[recipient],
                payload=payload,
                max_bytes=max_notice_bytes,
                now=now,
            )
    session.flush()
    record_event(
        session,
        actor,
        AuditEventType.PORTAL_CREATED,
        owner_id=actor.user_id,
        details={
            "portal_id": str(message.id),
            "recipients": len(recipients),
            "notify": notify,
            "view_seconds": view_seconds,
        },
        now=now,
    )
    return Created(message, links)


def _utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _by_token(session: Session, token: str, now: datetime, *, lock: bool = False) -> PortalLink:
    query = select(PortalLink).where(PortalLink.token_hash == token_hash(token))
    if lock:
        query = query.with_for_update()
    link = session.scalars(query).one_or_none()
    if link is None:
        raise ResourceNotFoundError()
    message = session.get(PortalMessage, link.portal_message_id)
    if message is None or _utc(message.expires_at) <= now:
        raise ResourceNotFoundError()  # expired: the purge removes it soon
    if link.viewable_until is not None and _utc(link.viewable_until) <= now:
        raise ResourceNotFoundError()  # view once: this link's window is over
    return link


@dataclass(frozen=True)
class Opened:
    link: PortalLink
    message: PortalMessage
    sender: str


def peek(session: Session, token: str, now: datetime) -> Opened:
    """What the page shows before the password: never starts a view-once window."""
    link = _by_token(session, token, now)
    message = session.get(PortalMessage, link.portal_message_id)
    assert message is not None
    return Opened(link, message, sender_address(session, message.sender_id))


def access(session: Session, token: str, now: datetime) -> Opened:
    """Hands out the envelope; for a view-once message, the first call opens the window."""
    link = _by_token(session, token, now, lock=True)
    message = session.get(PortalMessage, link.portal_message_id, with_for_update=True)
    assert message is not None
    link.last_access_at = now
    if message.view_seconds is not None and link.viewable_until is None:
        link.viewable_until = now + timedelta(seconds=message.view_seconds)
        session.flush()
        windows = [other.viewable_until for other in links_of(session, message.id)]
        if all(w is not None for w in windows):  # every link opened: delete after the last
            last = max(_utc(w) for w in windows if w is not None)
            message.expires_at = min(_utc(message.expires_at), last)
    session.flush()
    return Opened(link, message, sender_address(session, message.sender_id))


def sender_of(session: Session, token: str, now: datetime) -> uuid.UUID:
    link = _by_token(session, token, now)
    message = session.get(PortalMessage, link.portal_message_id)
    assert message is not None
    return message.sender_id


def reply(
    session: Session,
    token: str,
    *,
    pkesks: list[bytes],
    body: bytes,
    max_bytes: int,
    max_replies: int,
    now: datetime,
    quota: "QuotaPolicy | None" = None,
) -> int:
    """Store the reply in the sender's inbox; returns the link's reply count."""
    link = _by_token(session, token, now, lock=True)
    message = session.get(PortalMessage, link.portal_message_id)
    assert message is not None
    if message.view_seconds is not None or link.replies >= max_replies:
        raise ReplyLimitError()  # view-once links are read only
    if quota is not None:
        quota.require_recipient(session, message.sender_id, len(body), now)
    store_for_owner(
        session,
        message.sender_id,
        sender_id=None,
        origin=MessageOrigin.PORTAL,
        client_message_id=secrets.token_hex(16),
        pkesks=pkesks,
        body=body,
        max_bytes=max_bytes,
        now=now,
    )
    link.replies += 1
    session.flush()
    return link.replies


def links_of(session: Session, message_id: uuid.UUID) -> list[PortalLink]:
    return list(
        session.scalars(
            select(PortalLink)
            .where(PortalLink.portal_message_id == message_id)
            .order_by(PortalLink.recipient)
        )
    )


def get_own(session: Session, owner_id: uuid.UUID, message_id: uuid.UUID) -> PortalMessage:
    message = session.get(PortalMessage, message_id)
    if message is None or message.sender_id != owner_id:
        raise ResourceNotFoundError()
    return message


def list_own(
    session: Session, owner_id: uuid.UUID, *, limit: int, offset: int
) -> list[PortalMessage]:
    return list(
        session.scalars(
            select(PortalMessage)
            .where(PortalMessage.sender_id == owner_id)
            .order_by(PortalMessage.created_at.desc(), PortalMessage.id)
            .limit(limit)
            .offset(offset)
        )
    )


def delete_own(session: Session, actor: ActorContext, message_id: uuid.UUID, now: datetime) -> None:
    message = get_own(session, actor.user_id, message_id)
    session.execute(delete(PortalLink).where(PortalLink.portal_message_id == message.id))
    add_usage(session, actor.user_id, -message.size)
    session.delete(message)
    session.flush()
    record_event(
        session,
        actor,
        AuditEventType.PORTAL_DELETED,
        owner_id=actor.user_id,
        details={"portal_id": str(message_id)},
        now=now,
    )


def purge_expired(session: Session, now: datetime) -> int:
    rows = session.execute(
        select(PortalMessage.id, PortalMessage.sender_id, PortalMessage.size).where(
            PortalMessage.expires_at <= now
        )
    ).all()
    expired = [row[0] for row in rows]
    for _, sender_id, size in rows:
        add_usage(session, sender_id, -size)
    if expired:
        session.execute(delete(PortalLink).where(PortalLink.portal_message_id.in_(expired)))
        session.execute(delete(PortalMessage).where(PortalMessage.id.in_(expired)))
    return len(expired)
