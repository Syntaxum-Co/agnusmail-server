"""Schema-level guarantees for devices, public keys and audit events (entrega A).

Runs on SQLite (foreign keys enabled); PostgreSQL-only checks (format regex, append-only
trigger) are covered by tests/integration/test_devices_postgres.py.
"""

import secrets
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.modules.audit.models import AuditEvent
from agnusmail.modules.devices.models import Device, DeviceStatus
from agnusmail.modules.identity.models import User
from agnusmail.modules.keys.models import PublicKey, PublicKeyStatus
from tests.unit.fakes import make_session_factory

NOW = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)


def new_user(session: Session) -> User:
    user = User(ethereum_address="0x" + secrets.token_hex(20))
    session.add(user)
    session.flush()
    return user


def new_device(session: Session, user: User, **fields: Any) -> Device:
    device = Device(**{"user_id": user.id, "name": "laptop", **fields})
    session.add(device)
    session.flush()
    return device


def new_key(session: Session, device: Device, version: int = 1, **fields: Any) -> PublicKey:
    values: dict[str, Any] = {
        "user_id": device.user_id,
        "device_id": device.id,
        "version": version,
        "format": "test-format",
        "material": secrets.token_bytes(32),
        "material_digest": "sha256:" + secrets.token_hex(32),
        **fields,
    }
    key = PublicKey(**values)
    session.add(key)
    session.flush()
    return key


@pytest.fixture
def factory() -> sessionmaker[Session]:
    return make_session_factory()


def expect_integrity_error(factory: sessionmaker[Session], build: Any) -> None:
    with pytest.raises(IntegrityError), factory() as session, session.begin():
        build(session)


def test_key_must_belong_to_device_owner(factory: sessionmaker[Session]) -> None:
    with factory() as session, session.begin():
        owner, intruder = new_user(session), new_user(session)
        device = new_device(session, owner)
        device_id, intruder_id = device.id, intruder.id

    def foreign_key(session: Session) -> None:
        session.add(
            PublicKey(
                user_id=intruder_id,  # not the device owner
                device_id=device_id,
                version=1,
                format="test-format",
                material=b"x",
                material_digest="sha256:" + "0" * 64,
            )
        )
        session.flush()

    expect_integrity_error(factory, foreign_key)


def test_one_active_key_per_device_and_format(factory: sessionmaker[Session]) -> None:
    with factory() as session, session.begin():
        device = new_device(session, new_user(session))
        new_key(session, device, version=1)
        new_key(session, device, version=2, format="other-format")  # other format: fine
        device_id = device.id

    def second_active(session: Session) -> None:
        device = session.get(Device, device_id)
        assert device is not None
        new_key(session, device, version=3)

    expect_integrity_error(factory, second_active)

    with factory() as session, session.begin():
        reloaded = session.get(Device, device_id)
        assert reloaded is not None
        old = session.query(PublicKey).filter_by(device_id=device_id, version=1).one()
        old.status = PublicKeyStatus.SUPERSEDED
        old.superseded_at = NOW
        session.flush()
        new_key(session, reloaded, version=3)  # allowed once the previous one is superseded


def test_versions_are_unique_per_device(factory: sessionmaker[Session]) -> None:
    with factory() as session, session.begin():
        device = new_device(session, new_user(session))
        new_key(session, device, version=1)
        device_id = device.id

    def duplicate_version(session: Session) -> None:
        device = session.get(Device, device_id)
        assert device is not None
        new_key(session, device, version=1, format="other-format")

    expect_integrity_error(factory, duplicate_version)


def test_same_material_twice_for_one_user_is_rejected(factory: sessionmaker[Session]) -> None:
    digest = "sha256:" + "a" * 64
    with factory() as session, session.begin():
        user = new_user(session)
        first, second = new_device(session, user), new_device(session, user)
        new_key(session, first, material_digest=digest)
        second_id = second.id
        other_user_device = new_device(session, new_user(session))
        new_key(session, other_user_device, material_digest=digest)  # other user: allowed

    def reuse(session: Session) -> None:
        device = session.get(Device, second_id)
        assert device is not None
        new_key(session, device, material_digest=digest)

    expect_integrity_error(factory, reuse)


@pytest.mark.parametrize(
    "fields",
    [
        {"status": "unknown"},
        {"status": DeviceStatus.ACTIVE},  # active without authorized_at
        {"status": DeviceStatus.REVOKED},  # revoked without revoked_at
        {"status": DeviceStatus.PENDING, "revoked_at": NOW},  # timestamp without revocation
        {"name": ""},
    ],
)
def test_device_state_constraints(factory: sessionmaker[Session], fields: dict[str, Any]) -> None:
    def build(session: Session) -> None:
        new_device(session, new_user(session), **fields)

    expect_integrity_error(factory, build)


@pytest.mark.parametrize(
    "fields",
    [
        {"status": "unknown"},
        {"version": 0},
        {"material": b""},
        {"material_digest": "md5:" + "0" * 67},
        {"material_digest": "sha256:abc"},
        {"status": PublicKeyStatus.REVOKED},  # revoked without revoked_at
        {"status": PublicKeyStatus.SUPERSEDED},  # superseded without superseded_at
    ],
)
def test_public_key_constraints(factory: sessionmaker[Session], fields: dict[str, Any]) -> None:
    def build(session: Session) -> None:
        new_key(session, new_device(session, new_user(session)), **fields)

    expect_integrity_error(factory, build)


def chained_event(user_id: uuid.UUID, seq: int, event_type: str, **fields: Any) -> AuditEvent:
    """Raw row for schema tests (hash values are placeholders, not a valid chain)."""
    values: dict[str, Any] = {
        "chain_seq": seq,
        "prev_hash": bytes(32),
        "event_hash": bytes([seq % 256]) * 32,
        **fields,
    }
    return AuditEvent(user_id=user_id, event_type=event_type, **values)


def test_audit_event_types_are_constrained(factory: sessionmaker[Session]) -> None:
    with factory() as session, session.begin():
        user = new_user(session)
        session.add(chained_event(user.id, 1, "device.registered"))
        user_id = user.id

    def bad_type(session: Session) -> None:
        session.add(chained_event(user_id, 2, "device.deleted"))
        session.flush()

    expect_integrity_error(factory, bad_type)


@pytest.mark.parametrize(
    "fields",
    [
        {"chain_seq": 0},
        {"prev_hash": bytes(31)},
        {"event_hash": bytes(33)},
        {"chain_seq": 1},  # duplicate position in the same user's chain
    ],
)
def test_audit_chain_constraints(factory: sessionmaker[Session], fields: dict[str, Any]) -> None:
    with factory() as session, session.begin():
        user = new_user(session)
        session.add(chained_event(user.id, 1, "device.registered"))
        user_id = user.id

    def bad_row(session: Session) -> None:
        values = {"chain_seq": 2, **fields}
        session.add(chained_event(user_id, values.pop("chain_seq"), "key.revoked", **values))
        session.flush()

    expect_integrity_error(factory, bad_row)


def test_audit_event_ids_are_monotonic(factory: sessionmaker[Session]) -> None:
    with factory() as session, session.begin():
        user = new_user(session)
        events = [chained_event(user.id, n, "key.registered") for n in (1, 2, 3)]
        session.add_all(events)
        session.flush()
        ids = [event.id for event in events]
    assert ids == sorted(ids) and len(set(ids)) == 3


def test_unknown_user_or_device_is_rejected(factory: sessionmaker[Session]) -> None:
    def orphan_device(session: Session) -> None:
        session.add(Device(user_id=uuid.uuid4(), name="ghost"))
        session.flush()

    expect_integrity_error(factory, orphan_device)
