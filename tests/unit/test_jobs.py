"""Durable job queue and worker."""

import threading
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.modules.audit.models import AuditEvent, AuditEventType
from agnusmail.modules.audit.service import ActorContext, record_event
from agnusmail.modules.identity.models import User
from agnusmail.modules.jobs import worker as worker_module
from agnusmail.modules.jobs.handlers import REGISTRY, SCHEDULE
from agnusmail.modules.jobs.models import Job, JobStatus
from agnusmail.modules.jobs.queue import (
    InvalidPayloadError,
    JobContext,
    JobRegistry,
    JobSpec,
    backoff,
    check_payload,
    claim,
    complete,
    enqueue,
    reap_expired,
)
from agnusmail.modules.jobs.worker import Worker
from tests.unit.fakes import make_session_factory, make_settings

NOW = datetime(2026, 11, 12, 12, 0, tzinfo=UTC)
CALLS: list[tuple[str, dict[str, Any]]] = []


class BoomError(Exception):
    pass


def ok_handler(_ctx: JobContext, payload: Mapping[str, Any]) -> None:
    CALLS.append(("ok", dict(payload)))


def failing_handler(_ctx: JobContext, _payload: Mapping[str, Any]) -> None:
    raise BoomError("secret-looking detail 0xdeadbeef")


TEST_REGISTRY = JobRegistry(
    [
        JobSpec("test.ok", ok_handler, max_attempts=3, payload_keys=frozenset({"user_id", "n"})),
        JobSpec("test.fail", failing_handler, max_attempts=2),
    ]
)


@pytest.fixture(autouse=True)
def reset_calls() -> None:
    CALLS.clear()


@pytest.fixture
def factory() -> sessionmaker[Session]:
    return make_session_factory()


def add(factory: sessionmaker[Session], kind: str, **kwargs: Any) -> None:
    with factory() as session, session.begin():
        enqueue(session, TEST_REGISTRY, kind, now=NOW, **kwargs)


def jobs(factory: sessionmaker[Session]) -> list[Job]:
    with factory() as session:
        return list(session.scalars(select(Job).order_by(Job.id)))


def make_worker(factory: sessionmaker[Session], **kwargs: Any) -> Worker:
    return Worker(
        factory,
        make_settings(),
        registry=kwargs.pop("registry", TEST_REGISTRY),
        schedule=kwargs.pop("schedule", ()),
        worker_id=kwargs.pop("worker_id", "w1"),
    )


# --- payload and registry ------------------------------------------------------------


def test_payload_is_allowlisted_scalar_and_small() -> None:
    spec = TEST_REGISTRY.get("test.ok")
    assert check_payload(spec, {"user_id": "abc", "n": 3}) == {"user_id": "abc", "n": 3}
    for bad in ({"body": "hello"}, {"n": 1.5}, {"n": [1]}, {"user_id": "x" * 3000}):
        with pytest.raises(InvalidPayloadError):
            check_payload(spec, bad)


def test_registry_rejects_unknown_and_duplicate_kinds() -> None:
    with pytest.raises(ValueError, match="unknown"):
        TEST_REGISTRY.get("nope")
    with pytest.raises(ValueError, match="duplicate"):
        JobRegistry([JobSpec("a", ok_handler), JobSpec("a", ok_handler)])


def test_backoff_is_exponential_and_capped() -> None:
    assert [backoff(n).total_seconds() for n in (1, 2, 3)] == [30, 60, 120]
    assert backoff(30).total_seconds() == 3600


# --- lifecycle ------------------------------------------------------------------------


def test_job_runs_once_and_succeeds(factory: sessionmaker[Session]) -> None:
    add(factory, "test.ok", payload={"user_id": "u1"})
    assert make_worker(factory).run_once(NOW) == 1
    assert make_worker(factory).run_once(NOW) == 0
    assert CALLS == [("ok", {"user_id": "u1"})]
    (job,) = jobs(factory)
    assert (job.status, job.attempts, job.locked_by, job.last_error) == (
        JobStatus.SUCCEEDED,
        1,
        None,
        None,
    )


def test_future_jobs_wait_for_run_at(factory: sessionmaker[Session]) -> None:
    add(factory, "test.ok", run_at=NOW + timedelta(minutes=5))
    assert make_worker(factory).run_once(NOW) == 0
    assert make_worker(factory).run_once(NOW + timedelta(minutes=5)) == 1


def test_failures_back_off_then_die_without_leaking_messages(
    factory: sessionmaker[Session], capsys: pytest.CaptureFixture[str]
) -> None:
    add(factory, "test.fail")
    worker = make_worker(factory)
    worker.run_once(NOW)
    (job,) = jobs(factory)
    assert (job.status, job.attempts, job.last_error) == (JobStatus.QUEUED, 1, "BoomError")
    run_at = job.run_at.replace(tzinfo=UTC) if job.run_at.tzinfo is None else job.run_at
    assert run_at > NOW  # backoff
    worker.run_once(run_at)
    (job,) = jobs(factory)
    assert (job.status, job.attempts) == (JobStatus.DEAD, 2)
    assert job.finished_at is not None
    output = capsys.readouterr()
    assert "deadbeef" not in output.out + output.err


def test_expired_lease_is_reaped_and_stale_owner_cannot_finish(
    factory: sessionmaker[Session],
) -> None:
    add(factory, "test.ok")
    stale = claim(factory, "dead-worker", now=NOW, lease_seconds=60)
    assert stale is not None
    later = NOW + timedelta(seconds=61)
    assert reap_expired(factory, later) == 1
    (job,) = jobs(factory)
    assert (job.status, job.last_error) == (JobStatus.QUEUED, "LeaseExpired")
    assert make_worker(factory, worker_id="w2").run_once(later) == 1
    assert not complete(factory, stale, "dead-worker", later)  # lease lost
    (job,) = jobs(factory)
    assert (job.status, job.attempts) == (JobStatus.SUCCEEDED, 2)


def test_lease_expiry_on_the_last_attempt_kills_the_job(factory: sessionmaker[Session]) -> None:
    add(factory, "test.fail")  # max_attempts = 2
    for attempt in range(2):
        moment = NOW + timedelta(hours=attempt)
        assert claim(factory, "crashy", now=moment, lease_seconds=60) is not None
        reap_expired(factory, moment + timedelta(seconds=61))
    (job,) = jobs(factory)
    assert job.status == JobStatus.DEAD


def test_unknown_kind_in_the_table_fails_instead_of_crashing(
    factory: sessionmaker[Session],
) -> None:
    with factory() as session, session.begin():
        session.add(Job(kind="gone.kind", payload={}, status="queued", run_at=NOW, max_attempts=1))
    make_worker(factory).run_once(NOW)
    (job,) = jobs(factory)
    assert (job.status, job.last_error) == (JobStatus.DEAD, "ValueError")


def test_batch_size_bounds_one_iteration(factory: sessionmaker[Session]) -> None:
    for n in range(15):
        add(factory, "test.ok", payload={"n": n})
    worker = make_worker(factory)  # default batch size 10
    assert worker.run_once(NOW) == 10
    assert worker.run_once(NOW) == 5


# --- periodic schedule ----------------------------------------------------------------


def test_periodic_jobs_are_enqueued_once_per_period_by_many_workers(
    factory: sessionmaker[Session],
) -> None:
    workers = [Worker(factory, make_settings(), worker_id=f"w{n}") for n in range(3)]
    created = sum(w.schedule_periodic(NOW) for w in workers)
    assert created == len(SCHEDULE)
    hourly = [p for p in SCHEDULE if p.every <= timedelta(hours=1)]
    # One hour later only the (at least) hourly jobs are due again; one day later all.
    assert workers[0].schedule_periodic(NOW + timedelta(hours=1)) == len(hourly)
    assert workers[1].schedule_periodic(NOW + timedelta(hours=1)) == 0  # deduplicated
    assert workers[0].schedule_periodic(NOW + timedelta(days=1)) == len(SCHEDULE)
    kinds = sorted(j.kind for j in jobs(factory))
    assert kinds == sorted([p.kind for p in SCHEDULE] * 2 + [p.kind for p in hourly])


# --- real handlers --------------------------------------------------------------------


def new_user(factory: sessionmaker[Session]) -> uuid.UUID:
    with factory() as session, session.begin():
        user = User(ethereum_address="0x" + uuid.uuid4().hex + "00000000")
        session.add(user)
        session.flush()
        return user.id


def test_audit_jobs_purge_and_detect_broken_chains(factory: sessionmaker[Session]) -> None:
    old = datetime.now(UTC) - timedelta(days=400)
    healthy, damaged = new_user(factory), new_user(factory)
    with factory() as session, session.begin():
        for owner in (healthy, damaged):
            for _ in range(2):
                record_event(
                    session,
                    ActorContext(user_id=owner),
                    AuditEventType.KEY_REGISTERED,
                    owner_id=owner,
                    now=old,
                )
    now = datetime.now(UTC)
    worker = Worker(factory, make_settings(), registry=REGISTRY, schedule=())
    with factory() as session, session.begin():
        enqueue(session, REGISTRY, "audit.purge", now=now)
    worker.run_once(now)
    with factory() as session:
        remaining = session.scalars(
            select(AuditEvent.event_type).where(AuditEvent.user_id == healthy)
        ).all()
    assert remaining == ["audit.purged"]

    with factory() as session, session.begin():
        event = session.scalars(select(AuditEvent).where(AuditEvent.user_id == damaged)).first()
        assert event is not None
        event.event_type = "device.revoked"  # tampering (SQLite has no trigger)
        enqueue(session, REGISTRY, "audit.verify", now=now)
    worker.run_once(now)
    verify_job = [j for j in jobs(factory) if j.kind == "audit.verify"][0]
    assert verify_job.status == JobStatus.DEAD
    assert verify_job.last_error == "AuditVerificationFailedError"


def test_cleanup_removes_only_old_finished_jobs(factory: sessionmaker[Session]) -> None:
    long_ago = datetime.now(UTC) - timedelta(days=31)
    with factory() as session, session.begin():
        for status, finished in (
            ("succeeded", long_ago),
            ("dead", long_ago),
            ("succeeded", datetime.now(UTC)),
        ):
            session.add(
                Job(
                    kind="audit.verify",
                    payload={},
                    status=status,
                    run_at=long_ago,
                    max_attempts=1,
                    finished_at=finished,
                )
            )
        enqueue(session, REGISTRY, "jobs.cleanup", now=datetime.now(UTC))
    Worker(factory, make_settings(), schedule=()).run_once()
    statuses = sorted((j.kind, j.status) for j in jobs(factory))
    assert statuses == [("audit.verify", "succeeded"), ("jobs.cleanup", "succeeded")]


# --- loop -----------------------------------------------------------------------------


def test_run_forever_survives_iteration_errors_and_stops(
    factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    worker = make_worker(factory)
    stop = threading.Event()
    calls = 0

    def flaky(now: datetime | None = None) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise ConnectionError("database down")
        stop.set()
        return 0

    monkeypatch.setattr(worker, "run_once", flaky)
    monkeypatch.setattr(worker.settings, "worker_poll_seconds", 0.01)
    worker.run_forever(stop)
    assert calls == 2


def test_default_worker_id_is_bounded() -> None:
    assert 0 < len(worker_module.default_worker_id()) <= 128
