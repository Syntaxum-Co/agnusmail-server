"""Queue operations: enqueue, claim with lease, complete, fail, reap, clean up.

Claiming uses ``SELECT … FOR UPDATE SKIP LOCKED`` in a short transaction: concurrent
workers never take the same job and never wait on each other. The handler runs outside
that transaction, and the outcome is written in another short one, guarded by
``locked_by`` so a worker whose lease expired cannot overwrite the new owner's result.
"""

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import CursorResult, delete, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.core.config import Settings
from agnusmail.modules.jobs.models import MAX_PAYLOAD_BYTES, Job, JobStatus

BACKOFF_BASE_SECONDS = 30
BACKOFF_MAX_SECONDS = 3600


@dataclass(frozen=True)
class JobContext:
    factory: sessionmaker[Session]
    settings: Settings


Handler = Callable[[JobContext, Mapping[str, Any]], None]


@dataclass(frozen=True)
class JobSpec:
    kind: str
    handler: Handler
    max_attempts: int = 5
    payload_keys: frozenset[str] = frozenset()


class JobRegistry:
    def __init__(self, specs: list[JobSpec]) -> None:
        self._specs = {spec.kind: spec for spec in specs}
        if len(self._specs) != len(specs):
            raise ValueError("duplicate job kind")

    def get(self, kind: str) -> JobSpec:
        try:
            return self._specs[kind]
        except KeyError:
            raise ValueError(f"unknown job kind {kind!r}") from None

    def kinds(self) -> list[str]:
        return sorted(self._specs)


class InvalidPayloadError(ValueError):
    pass


def check_payload(spec: JobSpec, payload: Mapping[str, Any]) -> dict[str, Any]:
    """Only allowlisted keys with scalar values; never content."""
    unknown = set(payload) - spec.payload_keys
    if unknown:
        raise InvalidPayloadError(f"payload keys not allowed for {spec.kind}: {sorted(unknown)}")
    for key, value in payload.items():
        if value is not None and not isinstance(value, (bool, int, str)):
            raise InvalidPayloadError(f"payload value for {key!r} must be a scalar")
    clean = dict(payload)
    if len(json.dumps(clean).encode()) > MAX_PAYLOAD_BYTES:
        raise InvalidPayloadError("payload too large")
    return clean


def enqueue(
    session: Session,
    registry: JobRegistry,
    kind: str,
    payload: Mapping[str, Any] | None = None,
    *,
    now: datetime,
    run_at: datetime | None = None,
    dedupe_key: str | None = None,
) -> bool:
    """Insert a job; with ``dedupe_key`` an existing job with that key wins (returns False)."""
    spec = registry.get(kind)
    values = {
        "kind": kind,
        "payload": check_payload(spec, payload or {}),
        "status": JobStatus.QUEUED,
        "run_at": run_at or now,
        "attempts": 0,
        "max_attempts": spec.max_attempts,
        "dedupe_key": dedupe_key,
        "created_at": now,
    }
    if dedupe_key is None:
        session.add(Job(**values))
        session.flush()
        return True
    dialect = session.get_bind().dialect.name
    insert: Any = pg_insert(Job) if dialect == "postgresql" else sqlite_insert(Job)
    # RETURNING yields a row only when the insert happened (rowcount is not reliable for
    # ORM-enabled inserts with ON CONFLICT DO NOTHING on PostgreSQL).
    inserted = session.execute(
        insert.values(**values)
        .on_conflict_do_nothing(index_elements=["dedupe_key"])
        .returning(Job.id)
    ).first()
    return inserted is not None


@dataclass(frozen=True)
class ClaimedJob:
    id: int
    kind: str
    payload: dict[str, Any]
    attempts: int
    max_attempts: int


def claim(
    factory: sessionmaker[Session], worker_id: str, *, now: datetime, lease_seconds: int
) -> ClaimedJob | None:
    with factory() as session, session.begin():
        job = session.scalars(
            select(Job)
            .where(Job.status == JobStatus.QUEUED, Job.run_at <= now)
            .order_by(Job.run_at, Job.id)
            .limit(1)
            .with_for_update(skip_locked=True)
        ).first()
        if job is None:
            return None
        job.status = JobStatus.RUNNING
        job.attempts += 1
        job.locked_by = worker_id
        job.locked_until = now + timedelta(seconds=lease_seconds)
        return ClaimedJob(job.id, job.kind, dict(job.payload), job.attempts, job.max_attempts)


def _owned(job_id: int, worker_id: str) -> Any:
    return (Job.id == job_id) & (Job.status == JobStatus.RUNNING) & (Job.locked_by == worker_id)


def complete(
    factory: sessionmaker[Session], job: ClaimedJob, worker_id: str, now: datetime
) -> bool:
    with factory() as session, session.begin():
        result: CursorResult[Any] = session.execute(  # type: ignore[assignment]
            update(Job)
            .where(_owned(job.id, worker_id))
            .values(
                status=JobStatus.SUCCEEDED,
                locked_by=None,
                locked_until=None,
                last_error=None,
                finished_at=now,
            )
        )
        return bool(result.rowcount)


def backoff(attempts: int) -> timedelta:
    return timedelta(seconds=min(BACKOFF_BASE_SECONDS * 2 ** (attempts - 1), BACKOFF_MAX_SECONDS))


def fail(
    factory: sessionmaker[Session],
    job: ClaimedJob,
    worker_id: str,
    error_type: str,
    now: datetime,
) -> JobStatus | None:
    """Retry with exponential backoff, or give up (``dead``) after ``max_attempts``."""
    dead = job.attempts >= job.max_attempts
    status = JobStatus.DEAD if dead else JobStatus.QUEUED
    with factory() as session, session.begin():
        result: CursorResult[Any] = session.execute(  # type: ignore[assignment]
            update(Job)
            .where(_owned(job.id, worker_id))
            .values(
                status=status,
                locked_by=None,
                locked_until=None,
                last_error=error_type[:128],
                run_at=now if dead else now + backoff(job.attempts),
                finished_at=now if dead else None,
            )
        )
        return status if result.rowcount else None


def reap_expired(factory: sessionmaker[Session], now: datetime) -> int:
    """Leases that expired (worker died): requeue, or ``dead`` if attempts are used up."""
    with factory() as session, session.begin():
        expired = session.scalars(
            select(Job)
            .where(Job.status == JobStatus.RUNNING, Job.locked_until < now)
            .with_for_update(skip_locked=True)
        ).all()
        for job in expired:
            dead = job.attempts >= job.max_attempts
            job.status = JobStatus.DEAD if dead else JobStatus.QUEUED
            job.locked_by = None
            job.locked_until = None
            job.last_error = "LeaseExpired"
            job.run_at = now
            job.finished_at = now if dead else None
        return len(expired)


def delete_finished(session: Session, older_than: datetime) -> int:
    result: CursorResult[Any] = session.execute(  # type: ignore[assignment]
        delete(Job).where(
            Job.status.in_([JobStatus.SUCCEEDED, JobStatus.DEAD]),
            Job.finished_at < older_than,
        )
    )
    return int(result.rowcount or 0)
