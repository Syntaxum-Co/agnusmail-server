"""Reputation from metadata. Never reads message content."""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agnusmail.core.config import Settings
from agnusmail.core.exceptions import AgnusmailError, ConflictError, InvalidStateError
from agnusmail.modules.abuse.models import (
    AbuseReport,
    AccountRestriction,
    ReportCategory,
    RestrictionReason,
)
from agnusmail.modules.audit.models import AuditEventType
from agnusmail.modules.audit.service import ActorContext, record_event
from agnusmail.modules.messages.models import MailboxEntry, Message
from agnusmail.modules.outbound.models import OutboundMessage, OutboundRecipient, RecipientStatus


class AccountRestrictedError(AgnusmailError):
    status_code = 403
    message = "sending outside Agnusmail is suspended for this account for now"
    code = "ACCOUNT_RESTRICTED"


@dataclass(frozen=True)
class Thresholds:
    reporters: int
    report_window: timedelta
    bounce_ratio: float
    bounce_minimum: int
    restriction: timedelta

    @classmethod
    def from_settings(cls, settings: Settings) -> "Thresholds":
        return cls(
            reporters=settings.abuse_report_threshold,
            report_window=timedelta(days=settings.abuse_report_window_days),
            bounce_ratio=settings.abuse_bounce_ratio,
            bounce_minimum=settings.abuse_bounce_minimum,
            restriction=timedelta(days=settings.abuse_restriction_days),
        )


def _utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def restriction(session: Session, user_id: uuid.UUID, now: datetime) -> AccountRestriction | None:
    row = session.get(AccountRestriction, user_id)
    if row is None or _utc(row.restricted_until) <= now:
        return None
    return row


def require_unrestricted(session: Session, user_id: uuid.UUID, now: datetime) -> None:
    if restriction(session, user_id, now) is not None:
        raise AccountRestrictedError()


def distinct_reporters(session: Session, user_id: uuid.UUID, since: datetime) -> int:
    count = session.scalar(
        select(func.count(func.distinct(AbuseReport.reporter_id))).where(
            AbuseReport.reported_id == user_id, AbuseReport.created_at > since
        )
    )
    return int(count or 0)


def bounce_stats(session: Session, user_id: uuid.UUID, since: datetime) -> tuple[int, int]:
    """(permanent failures with a 5xx reply, settled recipients) of recent outbound mail.
    Expired and policy refusals do not count: they say nothing about the recipients."""
    rows = session.execute(
        select(OutboundRecipient.status, OutboundRecipient.smtp_code)
        .join(OutboundMessage, OutboundMessage.id == OutboundRecipient.outbound_message_id)
        .where(
            OutboundMessage.user_id == user_id,
            OutboundRecipient.updated_at > since,
            OutboundRecipient.status != RecipientStatus.PENDING,
        )
    ).all()
    settled = [code for status, code in rows if status == RecipientStatus.DELIVERED or code]
    bounced = [
        code
        for status, code in rows
        if status == RecipientStatus.FAILED and code is not None and 500 <= code < 600
    ]
    return len(bounced), len(settled)


def evaluate(
    session: Session, user_id: uuid.UUID, thresholds: Thresholds, now: datetime
) -> AccountRestriction | None:
    """Restrict (or extend the restriction of) an account whose signals cross the
    thresholds; returns the restriction in force, if any."""
    reason: RestrictionReason | None = None
    if distinct_reporters(session, user_id, now - thresholds.report_window) >= thresholds.reporters:
        reason = RestrictionReason.REPORTS
    else:
        bounced, settled = bounce_stats(session, user_id, now - timedelta(days=1))
        if settled >= thresholds.bounce_minimum and bounced >= thresholds.bounce_ratio * settled:
            reason = RestrictionReason.BOUNCES
    current = session.get(AccountRestriction, user_id, with_for_update=True)
    if reason is None:
        return current if current is not None and _utc(current.restricted_until) > now else None
    until = now + thresholds.restriction
    if current is None:
        current = AccountRestriction(user_id=user_id, reason=reason, restricted_until=until)
        session.add(current)
        newly = True
    else:
        newly = _utc(current.restricted_until) <= now
        current.reason = reason
        current.restricted_until = until
        current.updated_at = now
    session.flush()
    if newly:
        record_event(
            session,
            None,
            AuditEventType.ABUSE_RESTRICTED,
            owner_id=user_id,
            details={"reason": str(reason), "until": until.isoformat()},
            now=now,
        )
    return current


def report(
    session: Session,
    actor: ActorContext,
    message_id: uuid.UUID,
    category: ReportCategory,
    thresholds: Thresholds,
    now: datetime,
) -> AbuseReport:
    """A holder of the message reports its sender. Metadata only."""
    from agnusmail.core.exceptions import ResourceNotFoundError

    held = session.scalar(
        select(MailboxEntry.id).where(
            MailboxEntry.message_id == message_id, MailboxEntry.user_id == actor.user_id
        )
    )
    # Only the sender column: the abuse module never loads a body, not even ciphertext.
    found = session.execute(select(Message.sender_id).where(Message.id == message_id)).first()
    if held is None or found is None:
        raise ResourceNotFoundError()
    sender_id = found[0]
    if sender_id is None:
        raise InvalidStateError("external messages are handled by the inbound antispam")
    if sender_id == actor.user_id:
        raise InvalidStateError("you cannot report your own message")
    if session.scalar(
        select(AbuseReport.id).where(
            AbuseReport.message_id == message_id, AbuseReport.reporter_id == actor.user_id
        )
    ):
        raise ConflictError("you already reported this message")
    row = AbuseReport(
        message_id=message_id,
        reporter_id=actor.user_id,
        reported_id=sender_id,
        category=category,
        created_at=now,
    )
    session.add(row)
    session.flush()
    record_event(
        session,
        actor,
        AuditEventType.ABUSE_REPORTED,
        owner_id=actor.user_id,
        details={"message_id": str(message_id), "category": str(category)},
        now=now,
    )
    evaluate(session, sender_id, thresholds, now)
    return row


def recent_outbound_senders(session: Session, since: datetime) -> list[uuid.UUID]:
    return list(
        session.scalars(
            select(OutboundMessage.user_id).distinct().where(OutboundMessage.finished_at > since)
        )
    )
