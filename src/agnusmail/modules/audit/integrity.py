"""Operator-side integrity checks and the retention purge of the audit chain.

The purge removes, per user, the oldest prefix of the chain whose events are all older
than the retention cutoff. Before deleting it verifies that prefix; a broken chain is
never purged (that would destroy the evidence). It then moves the checkpoint, appends
an ``audit.purged`` event and deletes. In PostgreSQL the delete trigger re-checks the
rules independently: purge mode, 365-day floor by the database clock, checkpoint.
"""

import uuid
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, func, select, text
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.core.logging import get_logger
from agnusmail.modules.audit.chain import ChainCheck, ChainedFields, verify_run
from agnusmail.modules.audit.models import AuditChainHead, AuditEvent, AuditEventType
from agnusmail.modules.audit.service import chained_fields, lock_chain_head, record_event

log = get_logger(__name__)

PURGE_MODE_SQL = "SELECT set_config('agnusmail.audit_purge', 'on', true)"


class AuditChainBrokenError(Exception):
    """Refusing to purge a chain that does not verify."""

    def __init__(self, user_id: uuid.UUID, reason: str) -> None:
        super().__init__(f"audit chain of {user_id} is broken: {reason}")
        self.user_id = user_id
        self.reason = reason


@dataclass(frozen=True)
class ChainReport:
    user_id: uuid.UUID
    ok: bool
    checked: int
    reason: str | None = None
    failed_seq: int | None = None


def database_now(session: Session) -> datetime:
    """The database clock (the delete trigger judges age by it, not by the app's)."""
    value = session.scalar(select(func.now()))
    assert isinstance(value, datetime)
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _stream(
    session: Session, owner_id: uuid.UUID, after_seq: int, through_seq: int | None = None
) -> Iterator[tuple[ChainedFields, bytes]]:
    query = (
        select(AuditEvent)
        .where(AuditEvent.user_id == owner_id, AuditEvent.chain_seq > after_seq)
        .order_by(AuditEvent.chain_seq)
        .execution_options(yield_per=500)
    )
    if through_seq is not None:
        query = query.where(AuditEvent.chain_seq <= through_seq)
    for event in session.scalars(query):
        yield chained_fields(event), event.event_hash


def _checkpoint_matches_last_purge(session: Session, head: AuditChainHead) -> bool:
    if head.purged_through_seq == 0:
        return True
    last_purge = session.scalars(
        select(AuditEvent)
        .where(
            AuditEvent.user_id == head.user_id,
            AuditEvent.event_type == AuditEventType.AUDIT_PURGED,
        )
        .order_by(AuditEvent.chain_seq.desc())
        .limit(1)
    ).one_or_none()
    return (
        last_purge is not None
        and last_purge.details.get("through_seq") == head.purged_through_seq
        and last_purge.details.get("through_hash") == head.purged_through_hash.hex()
    )


def verify_user_chain(session: Session, owner_id: uuid.UUID) -> ChainReport:
    """Full check: links and hashes, head consistency, checkpoint vs last purge event."""
    head = session.get(AuditChainHead, owner_id)
    if head is None:
        has_events = session.scalar(
            select(func.count()).select_from(AuditEvent).where(AuditEvent.user_id == owner_id)
        )
        return ChainReport(owner_id, not has_events, 0, None if not has_events else "no_head")
    leftover = session.scalar(
        select(func.count())
        .select_from(AuditEvent)
        .where(
            AuditEvent.user_id == owner_id,
            AuditEvent.chain_seq <= head.purged_through_seq,
        )
    )
    check = verify_run(
        _stream(session, owner_id, head.purged_through_seq),
        start_seq=head.purged_through_seq,
        start_hash=head.purged_through_hash,
    )
    if not check.ok:
        return ChainReport(owner_id, False, check.checked, check.reason, check.failed_seq)
    if (check.last_seq, check.last_hash) != (head.head_seq, head.head_hash):
        return ChainReport(owner_id, False, check.checked, "head_mismatch", check.last_seq + 1)
    if not _checkpoint_matches_last_purge(session, head):
        return ChainReport(owner_id, False, check.checked, "checkpoint_mismatch")
    if leftover:
        return ChainReport(owner_id, False, check.checked, "events_behind_checkpoint")
    return ChainReport(owner_id, True, check.checked)


def chain_owners(session: Session) -> list[uuid.UUID]:
    """Every user with a chain head or with events (events without a head are an error)."""
    heads = select(AuditChainHead.user_id)
    events = select(AuditEvent.user_id).distinct()
    return sorted(set(session.scalars(heads)) | set(session.scalars(events)))


@dataclass(frozen=True)
class PurgeOutcome:
    user_id: uuid.UUID
    deleted: int
    through_seq: int


def enable_purge_mode(session: Session) -> None:
    """Transaction-local flag the PostgreSQL triggers require for DELETE/checkpoint moves."""
    if session.get_bind().dialect.name == "postgresql":
        session.execute(text(PURGE_MODE_SQL))


def _purge_boundary(session: Session, head: AuditChainHead, cutoff: datetime) -> int:
    """Last sequence of the prefix whose events are all older than ``cutoff``."""
    first_recent = session.scalar(
        select(func.min(AuditEvent.chain_seq)).where(
            AuditEvent.user_id == head.user_id,
            AuditEvent.chain_seq > head.purged_through_seq,
            AuditEvent.created_at >= cutoff,
        )
    )
    return head.head_seq if first_recent is None else int(first_recent) - 1


def purge_user(
    session: Session, owner_id: uuid.UUID, *, cutoff: datetime, now: datetime | None = None
) -> PurgeOutcome | None:
    """Purge one user's expired prefix inside the caller's transaction."""
    enable_purge_mode(session)
    head = lock_chain_head(session, owner_id)
    start_seq, start_hash = head.purged_through_seq, head.purged_through_hash
    through_seq = _purge_boundary(session, head, cutoff)
    if through_seq <= start_seq:
        return None
    check: ChainCheck = verify_run(
        _stream(session, owner_id, start_seq, through_seq),
        start_seq=start_seq,
        start_hash=start_hash,
    )
    if not check.ok or check.last_seq != through_seq:
        raise AuditChainBrokenError(owner_id, check.reason or "incomplete")

    head.purged_through_seq = through_seq
    head.purged_through_hash = check.last_hash
    session.flush()
    record_event(
        session,
        None,
        AuditEventType.AUDIT_PURGED,
        owner_id=owner_id,
        details={
            "through_seq": through_seq,
            "through_hash": check.last_hash.hex(),
            "deleted": check.checked,
        },
        now=now,
    )
    session.execute(
        delete(AuditEvent)
        .where(AuditEvent.user_id == owner_id, AuditEvent.chain_seq <= through_seq)
        .execution_options(synchronize_session=False)
    )
    return PurgeOutcome(owner_id, check.checked, through_seq)


@dataclass
class PurgeReport:
    cutoff: datetime
    purged: list[PurgeOutcome] = field(default_factory=list)
    broken: list[uuid.UUID] = field(default_factory=list)
    failed: list[uuid.UUID] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.broken and not self.failed


def _purge_one(
    factory: sessionmaker[Session], owner_id: uuid.UUID, cutoff: datetime, *, dry_run: bool
) -> PurgeOutcome | None:
    if not dry_run:
        with factory() as session, session.begin():
            return purge_user(session, owner_id, cutoff=cutoff)
    # Dry run: do everything (the PostgreSQL triggers still check each delete), then undo.
    with factory() as session:
        try:
            return purge_user(session, owner_id, cutoff=cutoff)
        finally:
            session.rollback()


def purge_expired(
    factory: sessionmaker[Session],
    *,
    retention_days: int,
    users: Iterable[uuid.UUID] | None = None,
    dry_run: bool = False,
) -> PurgeReport:
    """Purge every user with expired events, one transaction per user."""
    with factory() as session:
        cutoff = database_now(session) - timedelta(days=retention_days)
        candidates = (
            sorted(set(users))
            if users is not None
            else list(
                session.scalars(
                    select(AuditEvent.user_id)
                    .where(AuditEvent.created_at < cutoff)
                    .distinct()
                    .order_by(AuditEvent.user_id)
                )
            )
        )
    report = PurgeReport(cutoff=cutoff)
    for owner_id in candidates:
        try:
            outcome = _purge_one(factory, owner_id, cutoff, dry_run=dry_run)
        except AuditChainBrokenError as exc:
            log.error("audit_purge_chain_broken", user_id=str(owner_id), reason=exc.reason)
            report.broken.append(owner_id)
            continue
        except Exception as exc:  # one user's failure must not stop the others
            log.error("audit_purge_failed", user_id=str(owner_id), error_type=type(exc).__name__)
            report.failed.append(owner_id)
            continue
        if outcome is not None:
            report.purged.append(outcome)
    return report
