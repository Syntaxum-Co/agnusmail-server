"""Submission to the outbound queue (protocol v1 §10).

The API never sees the message in clear: the client encrypted it to the outbound
service's key. Here only structure, routing metadata and limits are checked. The From
header is checked by the outbound service after decrypting (it is inside the ciphertext).
"""

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import select
from sqlalchemy.orm import Session

from agnusmail.core.exceptions import AgnusmailError, ConflictError, ResourceNotFoundError
from agnusmail.infrastructure.openpgp import EnvelopeRejectedError, single_recipient_message
from agnusmail.modules.addresses.service import active_addresses
from agnusmail.modules.audit.models import AuditEventType
from agnusmail.modules.audit.service import ActorContext, record_event
from agnusmail.modules.messages.models import MessageOrigin
from agnusmail.modules.messages.service import EnvelopeInvalidError, store_for_owner
from agnusmail.modules.outbound.models import (
    QUEUE_TTL,
    OutboundKey,
    OutboundKind,
    OutboundMessage,
    OutboundRecipient,
    OutboundStatus,
    RecipientStatus,
)
from agnusmail.modules.outbound.recipients import (
    InvalidRecipientError,
    domain_of,
    is_internal,
    normalize_recipient,
)

if TYPE_CHECKING:
    from agnusmail.modules.quotas.policy import QuotaPolicy

PROTECTION = "not-e2ee"  # label of every outbound message


class SenderAddressRequiredError(AgnusmailError):
    status_code = 409
    message = "claim an address before sending outside Agnusmail"
    code = "SENDER_ADDRESS_REQUIRED"


class SenderInvalidError(AgnusmailError):
    status_code = 422
    message = "the sender must be one of your active addresses"
    code = "SENDER_INVALID"


class OutboundRecipientInvalidError(AgnusmailError):
    status_code = 422
    message = "invalid external recipient"
    code = "RECIPIENT_INVALID"


class RecipientInternalError(AgnusmailError):
    """Agnusmail addresses are reached end to end (/v1/messages), never in clear."""

    status_code = 422
    message = "recipients on this service must be sent end-to-end encrypted"
    code = "RECIPIENT_INTERNAL"


class OutboundKeyChangedError(AgnusmailError):
    status_code = 409
    message = "the outbound key changed; fetch /v1/outbound/keys and encrypt again"
    code = "OUTBOUND_KEY_CHANGED"


class OutboundUnavailableError(AgnusmailError):
    status_code = 503
    message = "outbound delivery is not configured"
    code = "OUTBOUND_UNAVAILABLE"


@dataclass(frozen=True)
class SentCopy:
    """The sender's own E2EE copy for the Sent folder (spec §6 format)."""

    pkesks: list[bytes]
    body: bytes


def parse_recipients(addresses: list[str], mail_domain: str, maximum: int) -> list[str]:
    if not 1 <= len(addresses) <= maximum:
        raise OutboundRecipientInvalidError(f"between 1 and {maximum} recipients")
    normalized: list[str] = []
    seen: set[str] = set()
    for address in addresses:
        try:
            value = normalize_recipient(address)
        except InvalidRecipientError as exc:
            raise OutboundRecipientInvalidError(str(exc)) from exc
        if is_internal(value, mail_domain):
            raise RecipientInternalError()
        if value.lower() in seen:
            raise OutboundRecipientInvalidError("duplicate recipient")
        seen.add(value.lower())
        normalized.append(value)
    return normalized


def reject_hosted(session: Session, recipients: list[str]) -> None:
    """Recipients on a verified custom domain are Agnusmail users: E2EE only."""
    from agnusmail.modules.domains.service import hosted

    if hosted(session, {domain_of(r) for r in recipients}):
        raise RecipientInternalError()


def sender_address(session: Session, user_id: uuid.UUID, chosen: str | None = None) -> str:
    """The From/MAIL FROM address: ``chosen`` must be one of the account's active
    addresses (primary or enabled alias); default: the primary."""
    addresses = [a.email for a in active_addresses(session, user_id)]
    if not addresses:
        raise SenderAddressRequiredError()
    if chosen is None:
        return addresses[0]
    for address in addresses:
        if address == chosen.strip().lower():
            return address
    raise SenderInvalidError()


def current_keys(session: Session, now: datetime) -> list[OutboundKey]:
    """Usable queue keys, newest first (clients encrypt to the first)."""
    return list(
        session.scalars(
            select(OutboundKey)
            .where(OutboundKey.expires_at > now)
            .order_by(OutboundKey.created_at.desc())
        )
    )


def enqueue(
    session: Session,
    *,
    user_id: uuid.UUID,
    client_message_id: str,
    kind: OutboundKind,
    sender: str,
    recipients: list[str],
    payload: bytes,
    max_bytes: int,
    now: datetime,
) -> OutboundMessage:
    if len(payload) > max_bytes:
        raise EnvelopeInvalidError(f"payload exceeds {max_bytes} bytes")
    try:
        fingerprint = single_recipient_message(payload)
    except EnvelopeRejectedError as exc:
        raise EnvelopeInvalidError(f"payload: {exc.reason}") from exc
    keys = current_keys(session, now)
    if not keys:  # the outbound service never started (or its key expired)
        raise OutboundUnavailableError()
    if fingerprint not in {key.encryption_fingerprint for key in keys}:
        raise OutboundKeyChangedError()
    duplicate = session.scalar(
        select(OutboundMessage.id).where(
            OutboundMessage.user_id == user_id,
            OutboundMessage.client_message_id == client_message_id,
        )
    )
    if duplicate is not None:
        raise ConflictError("message_id already used by this sender")
    message = OutboundMessage(
        user_id=user_id,
        client_message_id=client_message_id,
        kind=kind,
        sender_address=sender,
        key_fingerprint=fingerprint,
        payload=payload,
        size=len(payload),
        status=OutboundStatus.QUEUED,
        attempts=0,
        next_attempt_at=now,
        expires_at=now + QUEUE_TTL,
        created_at=now,
    )
    session.add(message)
    session.flush()
    for address in recipients:
        session.add(
            OutboundRecipient(
                outbound_message_id=message.id,
                address=address,
                status=RecipientStatus.PENDING,
                updated_at=now,
            )
        )
    session.flush()
    return message


def submit(
    session: Session,
    actor: ActorContext,
    *,
    client_message_id: str,
    recipients: list[str],
    payload: bytes,
    sent_copy: SentCopy | None,
    max_bytes: int,
    sender: str | None = None,
    quota: "QuotaPolicy | None" = None,
    max_copy_bytes: int,
    now: datetime,
) -> OutboundMessage:
    """Queue a user's message for conventional delivery; optionally keep their own E2EE
    copy in Sent (``origin = outbound``). One transaction: all or nothing."""
    reject_hosted(session, recipients)
    from agnusmail.modules.abuse.service import require_unrestricted

    require_unrestricted(session, actor.user_id, now)  # abuse restriction
    if quota is not None:  # read-only accounts do not send; the Sent copy grows storage
        quota.require_space(
            session, actor.user_id, 0 if sent_copy is None else len(sent_copy.body), now
        )
    chosen = sender_address(session, actor.user_id, sender)
    message = enqueue(
        session,
        user_id=actor.user_id,
        client_message_id=client_message_id,
        kind=OutboundKind.MESSAGE,
        sender=chosen,
        recipients=recipients,
        payload=payload,
        max_bytes=max_bytes,
        now=now,
    )
    if sent_copy is not None:
        store_for_owner(
            session,
            actor.user_id,
            sender_id=actor.user_id,
            origin=MessageOrigin.OUTBOUND,
            client_message_id=client_message_id,
            pkesks=sent_copy.pkesks,
            body=sent_copy.body,
            max_bytes=max_copy_bytes,
            now=now,
        )
    record_event(
        session,
        actor,
        AuditEventType.OUTBOUND_SUBMITTED,
        owner_id=actor.user_id,
        details={"outbound_id": str(message.id), "recipients": len(recipients)},
        now=now,
    )
    return message


def recipients_of(session: Session, message_id: uuid.UUID) -> list[OutboundRecipient]:
    return list(
        session.scalars(
            select(OutboundRecipient)
            .where(OutboundRecipient.outbound_message_id == message_id)
            .order_by(OutboundRecipient.address)
        )
    )


def get_own(session: Session, owner_id: uuid.UUID, message_id: uuid.UUID) -> OutboundMessage:
    message = session.get(OutboundMessage, message_id)
    if message is None or message.user_id != owner_id:
        raise ResourceNotFoundError()
    return message


def list_own(
    session: Session, owner_id: uuid.UUID, *, limit: int, offset: int
) -> list[OutboundMessage]:
    return list(
        session.scalars(
            select(OutboundMessage)
            .where(OutboundMessage.user_id == owner_id)
            .order_by(OutboundMessage.created_at.desc(), OutboundMessage.id)
            .limit(limit)
            .offset(offset)
        )
    )
