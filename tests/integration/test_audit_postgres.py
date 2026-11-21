"""PostgreSQL integration tests for the audit hash chain and its triggers.

Requires `alembic upgrade head`. Rows are created under random users and never deleted
(only the guarded retention purge may delete, and only events older than 365 days).
"""

import secrets
import uuid
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import Engine, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.core.config import Settings
from agnusmail.infrastructure.database.session import create_db_engine
from agnusmail.infrastructure.database.transaction import run_sync_transaction
from agnusmail.modules.audit.chain import verify_run
from agnusmail.modules.audit.integrity import purge_expired, purge_user, verify_user_chain
from agnusmail.modules.audit.models import AuditChainHead, AuditEvent, AuditEventType
from agnusmail.modules.audit.service import ActorContext, chained_fields, record_event
from agnusmail.modules.identity.models import User

pytestmark = pytest.mark.integration


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


def new_user(factory: sessionmaker[Session]) -> uuid.UUID:
    with factory() as session, session.begin():
        user = User(ethereum_address="0x" + secrets.token_hex(20))
        session.add(user)
        session.flush()
        return user.id


def append(
    factory: sessionmaker[Session], owner: uuid.UUID, count: int = 1, *, age_days: int = 0
) -> None:
    moment = datetime.now(UTC) - timedelta(days=age_days)
    with factory() as session, session.begin():
        for _ in range(count):
            record_event(
                session,
                ActorContext(user_id=owner),
                AuditEventType.KEY_REGISTERED,
                owner_id=owner,
                now=moment,
            )


def remaining(factory: sessionmaker[Session], owner: uuid.UUID) -> list[int]:
    with factory() as session:
        query = (
            select(AuditEvent.chain_seq)
            .where(AuditEvent.user_id == owner)
            .order_by(AuditEvent.chain_seq)
        )
        return list(session.scalars(query))


def chain_is_valid(factory: sessionmaker[Session], owner: uuid.UUID) -> tuple[bool, int]:
    with factory() as session:
        head = session.get(AuditChainHead, owner)
        assert head is not None
        events = session.scalars(
            select(AuditEvent).where(AuditEvent.user_id == owner).order_by(AuditEvent.chain_seq)
        ).all()
        result = verify_run(
            ((chained_fields(e), e.event_hash) for e in events),
            start_seq=head.purged_through_seq,
            start_hash=head.purged_through_hash,
        )
        ok = result.ok and (result.last_seq, result.last_hash) == (head.head_seq, head.head_hash)
        return ok, result.checked


def test_hashes_survive_jsonb_and_timestamptz_round_trip(factory: sessionmaker[Session]) -> None:
    owner = new_user(factory)
    with factory() as session, session.begin():
        record_event(
            session,
            ActorContext(user_id=owner, client={"ua": "sha256:" + "ef" * 32, "net": "x"}),
            AuditEventType.DEVICE_REGISTERED,
            owner_id=owner,
            details={"z": 1, "a": [True, None, "ç"], "nested": {"b": 2, "a": "é"}},
        )
    assert chain_is_valid(factory, owner) == (True, 1)


def test_concurrent_appends_never_fork_the_chain(factory: sessionmaker[Session]) -> None:
    owner = new_user(factory)  # no head yet: the first appends also race to create it

    def work(_: int) -> None:
        run_sync_transaction(
            factory,
            lambda s: record_event(
                s, ActorContext(user_id=owner), AuditEventType.KEY_REGISTERED, owner_id=owner
            ),
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(work, range(24)))
    assert chain_is_valid(factory, owner) == (True, 24)


def expect_rejected(
    factory: sessionmaker[Session], statement: str, owner: uuid.UUID, *, purge_mode: bool
) -> str:
    with pytest.raises(DBAPIError) as caught, factory() as session, session.begin():
        if purge_mode:
            session.execute(text("SELECT set_config('agnusmail.audit_purge', 'on', true)"))
        session.execute(text(statement), {"owner": owner})
    return str(caught.value.orig)


def test_delete_requires_purge_mode_age_and_checkpoint(factory: sessionmaker[Session]) -> None:
    owner = new_user(factory)
    append(factory, owner, 2)
    delete = "DELETE FROM audit_events WHERE user_id = :owner"
    assert "append-only" in expect_rejected(factory, delete, owner, purge_mode=False)
    # Purge mode alone does not allow deleting recent events.
    assert "retention floor" in expect_rejected(factory, delete, owner, purge_mode=True)
    truncate = "TRUNCATE audit_events"
    assert "append-only" in expect_rejected(factory, truncate, owner, purge_mode=True)
    update = "UPDATE audit_events SET details = '{}' WHERE user_id = :owner"
    assert "append-only" in expect_rejected(factory, update, owner, purge_mode=True)
    assert chain_is_valid(factory, owner) == (True, 2)


def test_chain_heads_only_move_forward(factory: sessionmaker[Session]) -> None:
    owner = new_user(factory)
    append(factory, owner, 2)
    for statement in (
        "UPDATE audit_chain_heads SET head_seq = 1 WHERE user_id = :owner",
        # The checkpoint moves only in purge mode.
        "UPDATE audit_chain_heads SET purged_through_seq = 1 WHERE user_id = :owner",
        "DELETE FROM audit_chain_heads WHERE user_id = :owner",
        "TRUNCATE audit_chain_heads",
    ):
        expect_rejected(factory, statement, owner, purge_mode=False)
    # Even in purge mode the checkpoint cannot go back once moved.
    forward = "UPDATE audit_chain_heads SET purged_through_seq = 1 WHERE user_id = :owner"
    with factory() as session, session.begin():
        session.execute(text("SELECT set_config('agnusmail.audit_purge', 'on', true)"))
        session.execute(text(forward), {"owner": owner})
    back = "UPDATE audit_chain_heads SET purged_through_seq = 0 WHERE user_id = :owner"
    assert "forward" in expect_rejected(factory, back, owner, purge_mode=True)


def test_purge_deletes_expired_events_through_the_trigger(
    factory: sessionmaker[Session],
) -> None:
    owner = new_user(factory)
    append(factory, owner, 3, age_days=400)
    append(factory, owner, 2)

    dry = purge_expired(factory, retention_days=365, users=[owner], dry_run=True)
    assert dry.ok and [p.deleted for p in dry.purged] == [3]
    assert remaining(factory, owner) == [1, 2, 3, 4, 5]  # rolled back

    report = purge_expired(factory, retention_days=365, users=[owner])
    assert report.ok and [p.deleted for p in report.purged] == [3]
    assert remaining(factory, owner) == [4, 5, 6]
    with factory() as session:
        verified = verify_user_chain(session, owner)
    assert (verified.ok, verified.checked) == (True, 3)


def test_retention_floor_holds_even_if_the_app_asks_for_more(
    factory: sessionmaker[Session],
) -> None:
    """A compromised or misconfigured purge cannot delete recent events."""
    owner = new_user(factory)
    append(factory, owner, 2, age_days=400)
    append(factory, owner, 2, age_days=30)
    tomorrow = datetime.now(UTC) + timedelta(days=1)
    with pytest.raises(DBAPIError) as caught, factory() as session, session.begin():
        purge_user(session, owner, cutoff=tomorrow)
    assert "retention floor" in str(caught.value.orig)
    assert remaining(factory, owner) == [1, 2, 3, 4]  # whole transaction rolled back
    assert chain_is_valid(factory, owner) == (True, 4)


def test_appends_wait_for_a_running_purge(factory: sessionmaker[Session]) -> None:
    owner = new_user(factory)
    append(factory, owner, 2, age_days=400)
    cutoff = datetime.now(UTC) - timedelta(days=365)

    def concurrent_append(_: int) -> None:
        append(factory, owner)

    with factory() as session, ThreadPoolExecutor(max_workers=2) as pool:
        purge_user(session, owner, cutoff=cutoff)  # holds the head lock until commit
        futures = [pool.submit(concurrent_append, n) for n in range(2)]
        session.commit()
        for future in futures:
            future.result()
    assert remaining(factory, owner) == [3, 4, 5]
    with factory() as session:
        assert verify_user_chain(session, owner).ok
