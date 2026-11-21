"""Recording and reading the audit trail.

Every device/key change is written in the SAME transaction as the change itself, so the
trail cannot miss a committed change (and a rolled-back change leaves no event).

Appending locks the user's chain head (``audit_chain_heads``) for the rest of the
transaction: appends of one user are serialized, so the chain never forks. Callers take
their domain locks first and append last, which keeps a single lock order.
"""

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from agnusmail.modules.audit.chain import GENESIS_HASH, ChainedFields, compute_event_hash
from agnusmail.modules.audit.models import AuditChainHead, AuditEvent, AuditEventType


@dataclass(frozen=True)
class ActorContext:
    """Who is acting, plus the hashed client fingerprint (never raw IP/User-Agent)."""

    user_id: uuid.UUID
    client: dict[str, str] = field(default_factory=dict)


def lock_chain_head(session: Session, owner_id: uuid.UUID) -> AuditChainHead:
    """Return the owner's chain head, created if missing, locked until commit."""
    query = (
        select(AuditChainHead)
        .where(AuditChainHead.user_id == owner_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    head = session.scalars(query).one_or_none()
    if head is not None:
        return head
    dialect = session.get_bind().dialect.name
    if dialect == "postgresql":
        insert: Any = pg_insert(AuditChainHead)
    elif dialect == "sqlite":
        insert = sqlite_insert(AuditChainHead)
    else:  # pragma: no cover - only PostgreSQL (production) and SQLite (tests)
        raise RuntimeError(f"unsupported dialect {dialect}")
    # A concurrent first append may insert the row too; whoever loses waits, does nothing
    # and then locks the winner's row.
    session.execute(
        insert.values(
            user_id=owner_id,
            head_seq=0,
            head_hash=GENESIS_HASH,
            purged_through_seq=0,
            purged_through_hash=GENESIS_HASH,
            updated_at=datetime.now(UTC),
        ).on_conflict_do_nothing(index_elements=["user_id"])
    )
    return session.scalars(query).one()


def record_event(
    session: Session,
    actor: ActorContext | None,
    event_type: AuditEventType,
    *,
    owner_id: uuid.UUID,
    device_id: uuid.UUID | None = None,
    public_key_id: uuid.UUID | None = None,
    details: dict[str, Any] | None = None,
    now: datetime | None = None,
) -> AuditEvent:
    """Append an event to the owner's chain. ``actor=None`` means the system."""
    head = lock_chain_head(session, owner_id)
    created_at = now or datetime.now(UTC)
    payload: dict[str, Any] = dict(details or {})
    if actor is not None:
        payload["client"] = dict(actor.client)
    fields = ChainedFields(
        user_id=owner_id,
        chain_seq=head.head_seq + 1,
        prev_hash=head.head_hash,
        event_type=str(event_type),
        actor_user_id=None if actor is None else actor.user_id,
        device_id=device_id,
        public_key_id=public_key_id,
        details=payload,
        created_at=created_at,
    )
    event_hash = compute_event_hash(fields)
    event = AuditEvent(
        user_id=owner_id,
        actor_user_id=fields.actor_user_id,
        event_type=fields.event_type,
        device_id=device_id,
        public_key_id=public_key_id,
        details=payload,
        created_at=created_at,
        chain_seq=fields.chain_seq,
        prev_hash=fields.prev_hash,
        event_hash=event_hash,
    )
    session.add(event)
    head.head_seq = fields.chain_seq
    head.head_hash = event_hash
    head.updated_at = created_at
    session.flush()
    return event


def chained_fields(event: AuditEvent) -> ChainedFields:
    """The hashed view of a stored event."""
    return ChainedFields(
        user_id=event.user_id,
        chain_seq=event.chain_seq,
        prev_hash=event.prev_hash,
        event_type=event.event_type,
        actor_user_id=event.actor_user_id,
        device_id=event.device_id,
        public_key_id=event.public_key_id,
        details=event.details,
        created_at=event.created_at,
    )


def get_chain_head(session: Session, owner_id: uuid.UUID) -> AuditChainHead | None:
    return session.get(AuditChainHead, owner_id)


def list_chain(
    session: Session, owner_id: uuid.UUID, *, after_seq: int, limit: int
) -> list[AuditEvent]:
    """The owner's events in chain order, starting after ``after_seq``."""
    rows = session.scalars(
        select(AuditEvent)
        .where(AuditEvent.user_id == owner_id, AuditEvent.chain_seq > after_seq)
        .order_by(AuditEvent.chain_seq)
        .limit(limit)
    ).all()
    return list(rows)


def list_events(
    session: Session,
    owner_id: uuid.UUID,
    *,
    device_id: uuid.UUID | None = None,
    limit: int,
    offset: int,
) -> tuple[list[AuditEvent], int]:
    """Newest first. Always scoped to the owner."""
    conditions = [AuditEvent.user_id == owner_id]
    if device_id is not None:
        conditions.append(AuditEvent.device_id == device_id)
    total = session.scalar(select(func.count()).select_from(AuditEvent).where(*conditions))
    rows = session.scalars(
        select(AuditEvent)
        .where(*conditions)
        .order_by(AuditEvent.id.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return list(rows), int(total or 0)
