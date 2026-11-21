"""PostgreSQL integration tests for the job queue.

Jobs use a unique test-only kind per test and are deleted at teardown, so a real worker
on the same database never sees them.
"""

import secrets
from collections.abc import Iterator, Mapping
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import Engine, delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.core.config import Settings
from agnusmail.infrastructure.database.session import create_db_engine
from agnusmail.modules import models as _all_models  # noqa: F401  (resolves every FK)
from agnusmail.modules.jobs.models import Job, JobStatus
from agnusmail.modules.jobs.queue import JobContext, JobRegistry, JobSpec, claim, enqueue

pytestmark = pytest.mark.integration


def noop(_ctx: JobContext, _payload: Mapping[str, Any]) -> None:
    return None


@pytest.fixture
def engine() -> Iterator[Engine]:
    db_engine = create_db_engine(Settings(_env_file=None))  # type: ignore[call-arg]
    try:
        yield db_engine
    finally:
        db_engine.dispose()


@pytest.fixture
def factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False)


@pytest.fixture
def kind(factory: sessionmaker[Session]) -> Iterator[str]:
    """A unique test-only kind; its jobs are deleted afterwards so a real worker on the
    same database never picks them up."""
    value = f"it.{secrets.token_hex(6)}"
    yield value
    with factory() as session, session.begin():
        session.execute(delete(Job).where(Job.kind == value))


def test_concurrent_claims_never_take_the_same_job(
    factory: sessionmaker[Session], kind: str
) -> None:
    registry = JobRegistry([JobSpec(kind, noop)])
    # In the past, so these jobs are claimable now and sort before any real queued job.
    past = datetime(2000, 1, 1, tzinfo=UTC)
    with factory() as session, session.begin():
        for _ in range(40):
            enqueue(session, registry, kind, now=past)

    def drain(worker: int) -> list[int]:
        taken: list[int] = []
        while True:
            job = claim(factory, f"it-{worker}", now=datetime.now(UTC), lease_seconds=60)
            if job is None or job.kind != kind:
                return taken
            taken.append(job.id)

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(drain, range(6)))
    claimed = [job_id for batch in results for job_id in batch]
    assert len(claimed) == 40 and len(set(claimed)) == 40
    with factory() as session:
        statuses = set(session.scalars(select(Job.status).where(Job.kind == kind)))
    assert statuses == {JobStatus.RUNNING}


def test_dedupe_key_wins_under_concurrency(factory: sessionmaker[Session], kind: str) -> None:
    registry = JobRegistry([JobSpec(kind, noop)])
    key = f"periodic:{kind}:1"

    def schedule(_: int) -> bool:
        with factory() as session, session.begin():
            return enqueue(session, registry, kind, now=datetime.now(UTC), dedupe_key=key)

    with ThreadPoolExecutor(max_workers=8) as pool:
        created = list(pool.map(schedule, range(16)))
    assert created.count(True) == 1
    with factory() as session:
        assert len(session.scalars(select(Job.id).where(Job.dedupe_key == key)).all()) == 1


def test_postgres_caps_the_payload_size(factory: sessionmaker[Session], kind: str) -> None:
    with pytest.raises(IntegrityError), factory() as session, session.begin():
        session.add(
            Job(
                kind=kind,
                payload={"x": "y" * 3000},
                status="queued",
                run_at=datetime.now(UTC),
                max_attempts=1,
            )
        )


def test_running_job_needs_a_lease(factory: sessionmaker[Session], kind: str) -> None:
    with pytest.raises(IntegrityError), factory() as session, session.begin():
        session.add(
            Job(
                kind=kind,
                payload={},
                status="running",
                run_at=datetime.now(UTC),
                max_attempts=1,
            )
        )
