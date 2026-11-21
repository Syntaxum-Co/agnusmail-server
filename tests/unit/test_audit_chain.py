"""Per-user hash chain of the audit trail."""

import dataclasses
import importlib.util
import uuid
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.modules.audit.chain import (
    GENESIS_HASH,
    ChainedFields,
    NonCanonicalDetailsError,
    canonical_bytes,
    compute_event_hash,
    format_timestamp,
    verify_run,
)
from agnusmail.modules.audit.models import AuditChainHead, AuditEvent, AuditEventType
from agnusmail.modules.audit.service import ActorContext, chained_fields, record_event
from agnusmail.modules.identity.models import User
from tests.unit.auth_helpers import login
from tests.unit.fakes import make_app, make_session_factory

USER = uuid.UUID("00000000-0000-4000-8000-000000000001")
DEVICE = uuid.UUID("00000000-0000-4000-8000-000000000002")
T0 = datetime(2026, 11, 11, 12, 0, 0, 123456, tzinfo=UTC)

# Published test vectors (docs/specs/audit-chain-v1.md); recomputed independently.
VECTOR_1 = ChainedFields(
    user_id=USER,
    chain_seq=1,
    prev_hash=GENESIS_HASH,
    event_type="device.registered",
    actor_user_id=USER,
    device_id=DEVICE,
    public_key_id=None,
    details={"status": "pending", "client": {"ua": "sha256:" + "ab" * 32}},
    created_at=T0,
)
VECTOR_1_HASH = "b03855c21a5e7ebff30871591e7c3d41f99e08d7fe63be4341f7e30245c54630"
VECTOR_2_HASH = "a1d2567b8957acd427504d71f2b8520aa3b031acaab440683944999d22b49e92"


def vector_2() -> ChainedFields:
    return ChainedFields(
        user_id=USER,
        chain_seq=2,
        prev_hash=bytes.fromhex(VECTOR_1_HASH),
        event_type="audit.purged",
        actor_user_id=None,
        device_id=None,
        public_key_id=None,
        details={"through_seq": 1, "through_hash": VECTOR_1_HASH, "deleted": 1},
        created_at=datetime(2027, 11, 12, tzinfo=UTC),
    )


def test_canonical_encoding_and_vectors() -> None:
    assert canonical_bytes(VECTOR_1) == (
        b'{"actor_user_id":"00000000-0000-4000-8000-000000000001",'
        b'"created_at":"2026-11-11T12:00:00.123456Z",'
        b'"details":{"client":{"ua":"sha256:' + b"ab" * 32 + b'"},"status":"pending"},'
        b'"device_id":"00000000-0000-4000-8000-000000000002",'
        b'"event_type":"device.registered","prev_hash":"' + b"0" * 64 + b'",'
        b'"public_key_id":null,"seq":1,'
        b'"user_id":"00000000-0000-4000-8000-000000000001","v":1}'
    )
    assert compute_event_hash(VECTOR_1).hex() == VECTOR_1_HASH
    assert compute_event_hash(vector_2()).hex() == VECTOR_2_HASH


def test_timestamps_are_normalized_to_utc_microseconds() -> None:
    naive = datetime(2026, 1, 2, 3, 4, 5)
    brt = datetime(2026, 1, 2, 0, 4, 5, tzinfo=timezone(timedelta(hours=-3)))
    assert format_timestamp(naive) == "2026-01-02T03:04:05.000000Z"
    assert format_timestamp(brt) == "2026-01-02T03:04:05.000000Z"


@pytest.mark.parametrize(
    "details",
    [{"ratio": 0.5}, {"nested": {"x": 1.0}}, {"items": [object()]}, {1: "x"}, {"b": b"x"}],
)
def test_non_canonical_details_are_rejected(details: dict[Any, Any]) -> None:
    with pytest.raises(NonCanonicalDetailsError):
        compute_event_hash(dataclasses.replace(VECTOR_1, details=details))


@pytest.mark.parametrize(
    "change",
    [
        {"chain_seq": 2},
        {"prev_hash": b"\x01" * 32},
        {"event_type": "device.revoked"},
        {"actor_user_id": None},
        {"device_id": None},
        {"public_key_id": DEVICE},
        {"details": {"status": "active", "client": {"ua": "sha256:" + "ab" * 32}}},
        {"created_at": T0 + timedelta(microseconds=1)},
        {"user_id": DEVICE},
    ],
)
def test_every_field_is_committed(change: dict[str, Any]) -> None:
    assert compute_event_hash(dataclasses.replace(VECTOR_1, **change)).hex() != VECTOR_1_HASH


def test_verify_run_detects_gaps_reordering_and_tampering() -> None:
    first = (VECTOR_1, bytes.fromhex(VECTOR_1_HASH))
    second = (vector_2(), bytes.fromhex(VECTOR_2_HASH))
    ok = verify_run([first, second], start_seq=0, start_hash=GENESIS_HASH)
    assert ok.ok and ok.checked == 2 and ok.last_seq == 2
    assert ok.last_hash.hex() == VECTOR_2_HASH

    gap = verify_run([second], start_seq=0, start_hash=GENESIS_HASH)
    assert (gap.ok, gap.failed_seq, gap.reason) == (False, 2, "gap")
    swapped = verify_run([second, first], start_seq=0, start_hash=GENESIS_HASH)
    assert not swapped.ok
    tampered = (dataclasses.replace(VECTOR_1, details={"status": "x"}), first[1])
    bad = verify_run([tampered, second], start_seq=0, start_hash=GENESIS_HASH)
    assert (bad.ok, bad.failed_seq, bad.reason, bad.checked) == (False, 1, "event_hash", 0)
    # Resuming from a checkpoint (after a purge) needs the right checkpoint hash.
    resumed = verify_run([second], start_seq=1, start_hash=first[1])
    assert resumed.ok
    wrong = verify_run([second], start_seq=1, start_hash=GENESIS_HASH)
    assert (wrong.ok, wrong.reason) == (False, "prev_hash")


def test_migration_backfill_uses_the_same_version_1_hash() -> None:
    """The migration carries a frozen copy of the algorithm; it must stay identical."""
    path = next(Path("src/agnusmail/migrations/versions").glob("*_0003_audit_hash_chain.py"))
    spec = importlib.util.spec_from_file_location("migration_0003", path)
    assert spec is not None and spec.loader is not None
    module: ModuleType = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for fields in (VECTOR_1, vector_2()):
        values = {f.name: getattr(fields, f.name) for f in dataclasses.fields(fields)}
        assert module.hash_v1(**values) == compute_event_hash(fields)


# --- record_event over a real (SQLite) session ---------------------------------------


def new_user(factory: sessionmaker[Session]) -> uuid.UUID:
    with factory() as session, session.begin():
        user = User(ethereum_address="0x" + uuid.uuid4().hex + "00000000")
        session.add(user)
        session.flush()
        return user.id


def verify_user(session: Session, owner: uuid.UUID) -> tuple[bool, int]:
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
    consistent = result.last_seq == head.head_seq and result.last_hash == head.head_hash
    return result.ok and consistent, result.checked


def test_record_event_links_each_users_chain() -> None:
    factory = make_session_factory()
    alice, bob = new_user(factory), new_user(factory)
    actor = ActorContext(user_id=alice, client={"ua": "sha256:" + "cd" * 32})
    with factory() as session, session.begin():
        for _ in range(3):
            record_event(session, actor, AuditEventType.DEVICE_REGISTERED, owner_id=alice)
        record_event(session, None, AuditEventType.KEY_REVOKED, owner_id=bob)
    with factory() as session, session.begin():
        record_event(session, actor, AuditEventType.DEVICE_REVOKED, owner_id=alice)

    with factory() as session:
        events = session.scalars(
            select(AuditEvent).where(AuditEvent.user_id == alice).order_by(AuditEvent.chain_seq)
        ).all()
        assert [e.chain_seq for e in events] == [1, 2, 3, 4]
        assert events[0].prev_hash == GENESIS_HASH
        assert all(b.prev_hash == a.event_hash for a, b in zip(events, events[1:], strict=False))
        assert verify_user(session, alice) == (True, 4)
        assert verify_user(session, bob) == (True, 1)
        system = session.scalars(select(AuditEvent).where(AuditEvent.user_id == bob)).one()
        assert system.actor_user_id is None and "client" not in system.details
        assert system.prev_hash == GENESIS_HASH


def test_tampering_with_a_stored_event_is_detected() -> None:
    factory = make_session_factory()
    owner = new_user(factory)
    actor = ActorContext(user_id=owner)
    with factory() as session, session.begin():
        for _ in range(3):
            record_event(session, actor, AuditEventType.KEY_REGISTERED, owner_id=owner)
    # SQLite has no append-only trigger: simulate an attacker editing a row.
    with factory() as session, session.begin():
        middle = session.scalars(
            select(AuditEvent).where(AuditEvent.user_id == owner, AuditEvent.chain_seq == 2)
        ).one()
        middle.details = {"forged": True}
    with factory() as session:
        assert verify_user(session, owner) == (False, 1)


def test_rejected_details_leave_no_event_and_no_head_change() -> None:
    factory = make_session_factory()
    owner = new_user(factory)
    with pytest.raises(NonCanonicalDetailsError), factory() as session, session.begin():
        record_event(
            session,
            ActorContext(user_id=owner),
            AuditEventType.KEY_REGISTERED,
            owner_id=owner,
            details={"ratio": 0.5},
        )
    with factory() as session:
        assert session.get(AuditChainHead, owner) is None
        assert session.scalars(select(AuditEvent)).all() == []


# --- /v1/audit -------------------------------------------------------------------------


def recompute(owner: str, item: dict[str, Any]) -> str:
    """What a client does: rebuild the hashed fields from the JSON response."""

    def as_uuid(value: str | None) -> uuid.UUID | None:
        return None if value is None else uuid.UUID(value)

    fields = ChainedFields(
        user_id=uuid.UUID(owner),
        chain_seq=item["chain_seq"],
        prev_hash=bytes.fromhex(item["prev_hash"]),
        event_type=item["event_type"],
        actor_user_id=as_uuid(item["actor_user_id"]),
        device_id=as_uuid(item["device_id"]),
        public_key_id=as_uuid(item["public_key_id"]),
        details=item["details"],
        created_at=datetime.fromisoformat(item["created_at"]),
    )
    return compute_event_hash(fields).hex()


def test_api_exposes_a_chain_the_client_can_verify() -> None:
    app, _ = make_app()
    with TestClient(app, raise_server_exceptions=False) as client:
        assert client.get("/v1/audit/chain").status_code == 401
        user = login(client)
        after_login = client.get("/v1/audit/chain").json()
        assert after_login["head_seq"] == 1  # the login itself is the first event
        assert (after_login["purged_through_seq"], after_login["purged_through_hash"]) == (
            0,
            "00" * 32,
        )
        for name in ("a", "b", "c"):
            assert client.post("/v1/devices", json={"name": name}).status_code == 201

        head = client.get("/v1/audit/chain").json()
        first = client.get("/v1/audit/events", params={"limit": 2}).json()
        rest = client.get("/v1/audit/events", params={"after_seq": 2, "limit": 2}).json()

    assert head["head_seq"] == 4
    assert (first["has_more"], rest["has_more"]) == (True, False)
    items = first["items"] + rest["items"]
    assert [i["chain_seq"] for i in items] == [1, 2, 3, 4]
    assert [i["event_type"] for i in items] == ["auth.login"] + ["device.registered"] * 3
    previous = head["purged_through_hash"]
    for item in items:
        assert item["prev_hash"] == previous
        assert recompute(user.user_id, item) == item["event_hash"]
        previous = item["event_hash"]
    assert previous == head["head_hash"]


def test_audit_chain_is_scoped_to_the_caller() -> None:
    app, _ = make_app()
    with (
        TestClient(app, raise_server_exceptions=False) as alice,
        TestClient(app, raise_server_exceptions=False) as bob,
    ):
        login(alice)
        login(bob)
        alice.post("/v1/devices", json={"name": "alice-laptop"})
        assert [e["event_type"] for e in bob.get("/v1/audit/events").json()["items"]] == [
            "auth.login"
        ]
        assert bob.get("/v1/audit/chain").json()["head_seq"] == 1
        assert len(alice.get("/v1/audit/events").json()["items"]) == 2


@pytest.mark.parametrize("params", [{"after_seq": -1}, {"limit": 0}, {"limit": 201}])
def test_audit_events_query_bounds(params: dict[str, int]) -> None:
    app, _ = make_app()
    with TestClient(app, raise_server_exceptions=False) as client:
        login(client)
        assert client.get("/v1/audit/events", params=params).status_code == 422
