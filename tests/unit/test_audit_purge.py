"""Retention purge and full verification of the audit chain (4.3.3).

SQLite has no triggers: these tests cover the application logic. The database-side
rules (purge mode, 365-day floor, checkpoint) are covered by the PostgreSQL tests.
"""

import json
import subprocess
import sys
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import delete, select
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.modules.audit.cli import main
from agnusmail.modules.audit.integrity import (
    AuditChainBrokenError,
    purge_expired,
    purge_user,
    verify_user_chain,
)
from agnusmail.modules.audit.models import AuditChainHead, AuditEvent, AuditEventType
from agnusmail.modules.audit.service import ActorContext, record_event
from agnusmail.modules.identity.models import User
from tests.unit.auth_helpers import login
from tests.unit.fakes import make_app, make_session_factory, make_settings
from tests.unit.test_audit_chain import recompute

NOW = datetime.now(UTC)
OLD = NOW - timedelta(days=400)
CUTOFF = NOW - timedelta(days=365)


@pytest.fixture
def factory() -> sessionmaker[Session]:
    return make_session_factory()


def new_user(factory: sessionmaker[Session]) -> uuid.UUID:
    with factory() as session, session.begin():
        user = User(ethereum_address="0x" + uuid.uuid4().hex + "00000000")
        session.add(user)
        session.flush()
        return user.id


def append(factory: sessionmaker[Session], owner: uuid.UUID, *moments: datetime) -> None:
    with factory() as session, session.begin():
        for moment in moments:
            record_event(
                session,
                ActorContext(user_id=owner, client={"ua": "sha256:" + "aa" * 32}),
                AuditEventType.KEY_REGISTERED,
                owner_id=owner,
                details={"version": 1},
                now=moment,
            )


def sequences(factory: sessionmaker[Session], owner: uuid.UUID) -> list[int]:
    with factory() as session:
        return list(
            session.scalars(
                select(AuditEvent.chain_seq)
                .where(AuditEvent.user_id == owner)
                .order_by(AuditEvent.chain_seq)
            )
        )


def purge(factory: sessionmaker[Session], owner: uuid.UUID, cutoff: datetime = CUTOFF) -> object:
    with factory() as session, session.begin():
        return purge_user(session, owner, cutoff=cutoff, now=NOW)


def test_purge_removes_the_expired_prefix_and_keeps_the_chain_verifiable(
    factory: sessionmaker[Session],
) -> None:
    owner = new_user(factory)
    append(factory, owner, OLD, OLD, OLD, NOW, NOW)
    outcome = purge(factory, owner)
    assert outcome is not None
    assert (outcome.deleted, outcome.through_seq) == (3, 3)  # type: ignore[attr-defined]
    assert sequences(factory, owner) == [4, 5, 6]
    with factory() as session:
        head = session.get(AuditChainHead, owner)
        assert head is not None and head.purged_through_seq == 3
        marker = session.scalars(
            select(AuditEvent).where(AuditEvent.user_id == owner, AuditEvent.chain_seq == 6)
        ).one()
        assert marker.event_type == AuditEventType.AUDIT_PURGED
        assert marker.actor_user_id is None
        assert marker.details == {
            "through_seq": 3,
            "through_hash": head.purged_through_hash.hex(),
            "deleted": 3,
        }
        report = verify_user_chain(session, owner)
    assert (report.ok, report.checked) == (True, 3)


def test_purge_stops_at_the_first_recent_event(factory: sessionmaker[Session]) -> None:
    owner = new_user(factory)
    append(factory, owner, OLD, NOW, OLD)  # timestamps are not monotonic in the chain
    purge(factory, owner)
    assert sequences(factory, owner) == [2, 3, 4]


def test_nothing_expired_means_no_purge_event(factory: sessionmaker[Session]) -> None:
    owner = new_user(factory)
    append(factory, owner, NOW, NOW)
    assert purge(factory, owner) is None
    assert sequences(factory, owner) == [1, 2]
    with factory() as session:
        head = session.get(AuditChainHead, owner)
        assert head is not None and (head.head_seq, head.purged_through_seq) == (2, 0)


def test_successive_purges_chain_their_checkpoints(factory: sessionmaker[Session]) -> None:
    owner = new_user(factory)
    append(factory, owner, OLD, OLD)
    purge(factory, owner)  # deletes 1-2, appends purge event 3 (dated NOW)
    append(factory, owner, NOW)
    # A year later everything so far is expired, including the first purge event.
    later = NOW + timedelta(days=1)
    with factory() as session, session.begin():
        outcome = purge_user(session, owner, cutoff=later, now=later)
    assert outcome is not None and outcome.through_seq == 4
    assert sequences(factory, owner) == [5]
    with factory() as session:
        report = verify_user_chain(session, owner)
    assert report.ok, report


def test_a_broken_chain_is_never_purged(factory: sessionmaker[Session]) -> None:
    owner = new_user(factory)
    append(factory, owner, OLD, OLD, NOW)
    with factory() as session, session.begin():
        first = session.scalars(
            select(AuditEvent).where(AuditEvent.user_id == owner, AuditEvent.chain_seq == 1)
        ).one()
        first.details = {"version": 2}  # tampering (SQLite has no append-only trigger)
    with pytest.raises(AuditChainBrokenError) as caught:
        purge(factory, owner)
    assert caught.value.reason == "event_hash"
    assert sequences(factory, owner) == [1, 2, 3]  # evidence preserved


def test_verify_detects_each_kind_of_damage(factory: sessionmaker[Session]) -> None:
    def damaged(change: str) -> str | None:
        owner = new_user(factory)
        append(factory, owner, OLD, OLD, NOW)
        purge(factory, owner)  # checkpoint 2, events 3 and 4 remain
        with factory() as session, session.begin():
            head = session.get(AuditChainHead, owner)
            assert head is not None
            if change == "drop_tail":
                session.execute(
                    delete(AuditEvent).where(AuditEvent.user_id == owner, AuditEvent.chain_seq == 4)
                )
            elif change == "move_checkpoint":
                head.purged_through_seq, head.purged_through_hash = 0, bytes(32)
            elif change == "drop_head":
                session.delete(head)
            elif change == "reinsert_old":
                session.add(
                    AuditEvent(
                        user_id=owner,
                        event_type="key.registered",
                        details={},
                        created_at=OLD,
                        chain_seq=1,
                        prev_hash=bytes(32),
                        event_hash=bytes(32),
                    )
                )
        with factory() as session:
            report = verify_user_chain(session, owner)
        assert not report.ok
        return report.reason

    assert damaged("drop_tail") == "head_mismatch"
    assert damaged("move_checkpoint") == "gap"
    assert damaged("drop_head") == "no_head"
    assert damaged("reinsert_old") == "events_behind_checkpoint"


def test_verify_flags_a_checkpoint_without_its_purge_event(
    factory: sessionmaker[Session],
) -> None:
    owner = new_user(factory)
    append(factory, owner, OLD, OLD, NOW)
    # Simulate an unrecorded deletion: checkpoint moved, events deleted, no purge event.
    with factory() as session, session.begin():
        events = session.scalars(
            select(AuditEvent).where(AuditEvent.user_id == owner).order_by(AuditEvent.chain_seq)
        ).all()
        head = session.get(AuditChainHead, owner)
        assert head is not None
        head.purged_through_seq, head.purged_through_hash = 2, events[1].event_hash
        for event in events[:2]:
            session.delete(event)
    with factory() as session:
        assert verify_user_chain(session, owner).reason == "checkpoint_mismatch"


def test_purge_expired_and_dry_run(factory: sessionmaker[Session]) -> None:
    alice, bob, carol = new_user(factory), new_user(factory), new_user(factory)
    append(factory, alice, OLD, OLD, NOW)
    append(factory, bob, NOW)
    append(factory, carol, OLD)

    dry = purge_expired(factory, retention_days=365, dry_run=True)
    assert dry.ok
    assert sorted((p.user_id, p.deleted) for p in dry.purged) == sorted([(alice, 2), (carol, 1)])
    assert sequences(factory, alice) == [1, 2, 3]  # rolled back

    real = purge_expired(factory, retention_days=365)
    assert real.ok and len(real.purged) == 2
    assert sequences(factory, alice) == [3, 4]
    assert sequences(factory, bob) == [1]
    assert sequences(factory, carol) == [2]
    assert purge_expired(factory, retention_days=365).purged == []  # idempotent


def test_purge_expired_isolates_a_broken_chain(factory: sessionmaker[Session]) -> None:
    good, bad = new_user(factory), new_user(factory)
    append(factory, good, OLD)
    append(factory, bad, OLD)
    with factory() as session, session.begin():
        session.scalars(select(AuditEvent).where(AuditEvent.user_id == bad)).one().details = {}
    report = purge_expired(factory, retention_days=365)
    assert not report.ok
    assert report.broken == [bad]
    assert [p.user_id for p in report.purged] == [good]


def test_retention_cannot_be_shorter_than_365_days() -> None:
    with pytest.raises(ValidationError):
        make_settings(audit_retention_days=364)
    assert make_settings(audit_retention_days=730).audit_retention_days == 730


def test_cli_verify_and_purge(
    factory: sessionmaker[Session], capsys: pytest.CaptureFixture[str]
) -> None:
    owner = new_user(factory)
    append(factory, owner, OLD, NOW)
    settings = make_settings()

    assert main(["purge", "--dry-run"], settings=settings, factory=factory) == 0
    dry = json.loads(capsys.readouterr().out)
    assert (dry["dry_run"], dry["users_purged"], dry["events_deleted"]) == (True, 1, 1)

    assert main(["purge"], settings=settings, factory=factory) == 0
    assert json.loads(capsys.readouterr().out)["events_deleted"] == 1

    assert main(["verify"], settings=settings, factory=factory) == 0
    verified = json.loads(capsys.readouterr().out)
    assert (verified["ok"], verified["chains"], verified["broken"]) == (True, 1, [])

    with factory() as session, session.begin():
        event = session.scalars(select(AuditEvent).where(AuditEvent.user_id == owner)).first()
        assert event is not None
        event.event_type = "device.revoked"
    assert main(["verify", "--user", str(owner)], settings=settings, factory=factory) == 1
    output = capsys.readouterr().out
    broken = json.loads(output)["broken"]
    assert broken == [{"user_id": str(owner), "reason": "event_hash", "failed_seq": 2}]
    assert "details" not in output


def test_client_verifies_from_the_checkpoint_after_a_purge() -> None:
    factory = make_session_factory()
    app, _ = make_app(session_factory=factory)
    with TestClient(app, raise_server_exceptions=False) as client:
        user = login(client)
        for name in ("a", "b"):
            client.post("/v1/devices", json={"name": name})
        future = datetime.now(UTC) + timedelta(days=1)
        with factory() as session, session.begin():  # SQLite: no 365-day floor
            purge_user(session, uuid.UUID(user.user_id), cutoff=future)
        client.post("/v1/devices", json={"name": "c"})
        head = client.get("/v1/audit/chain").json()
        items = client.get(
            "/v1/audit/events", params={"after_seq": head["purged_through_seq"]}
        ).json()["items"]

    assert head["purged_through_seq"] == 3  # login + two devices
    assert [i["event_type"] for i in items] == ["audit.purged", "device.registered"]
    assert items[0]["details"]["through_hash"] == head["purged_through_hash"]
    previous = head["purged_through_hash"]
    for item in items:
        assert item["prev_hash"] == previous
        assert recompute(user.user_id, item) == item["event_hash"]
        previous = item["event_hash"]
    assert previous == head["head_hash"]


def test_cli_loads_every_model_in_a_fresh_interpreter() -> None:
    """Regression: alone, the audit models cannot resolve their FK to ``users``."""
    code = "; ".join(
        [
            "import agnusmail.modules.audit.cli",
            "from sqlalchemy import create_engine",
            "from agnusmail.infrastructure.database.base import Base",
            "Base.metadata.create_all(create_engine('sqlite://'))",
        ]
    )
    result = subprocess.run(  # noqa: S603  (fixed interpreter and code)
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=60, check=False
    )
    assert result.returncode == 0, result.stderr[-2000:]
