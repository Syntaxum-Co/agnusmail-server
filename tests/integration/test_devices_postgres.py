"""PostgreSQL integration tests for devices, public keys and the audit trail.

Requires `alembic upgrade head` (as in CI). Rows are created under random users and are
not deleted: the audit trail is append-only by design.
"""

import secrets
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import Engine, select, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.core.config import Settings
from agnusmail.core.exceptions import LimitExceededError
from agnusmail.infrastructure.database.session import create_db_engine
from agnusmail.infrastructure.database.transaction import run_sync_transaction
from agnusmail.infrastructure.openpgp import PROTOCOL_KEY_FORMAT
from agnusmail.modules.audit.models import AuditEvent, AuditEventType
from agnusmail.modules.audit.service import ActorContext, record_event
from agnusmail.modules.devices.models import Device
from agnusmail.modules.devices.service import DevicePolicy, register_device
from agnusmail.modules.identity.models import User
from agnusmail.modules.identity.repository import register_login
from agnusmail.modules.keys.models import PublicKey
from agnusmail.modules.keys.policy import (
    DeviceCertificatePolicy,
    RegistrationContext,
    registration_statement,
)
from agnusmail.modules.keys.service import KeyLimits, register_key
from tests.openpgp_helpers import new_device

SERVICE = "app.agnusmail"

pytestmark = pytest.mark.integration


@pytest.fixture
def settings_env() -> Settings:
    return Settings(_env_file=None)  # type: ignore[call-arg]


@pytest.fixture
def engine(settings_env: Settings) -> Iterator[Engine]:
    db_engine = create_db_engine(settings_env)
    try:
        yield db_engine
    finally:
        db_engine.dispose()


@pytest.fixture
def factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False)


def seed(factory: sessionmaker[Session]) -> tuple[User, Device]:
    with factory() as session, session.begin():
        user = User(ethereum_address="0x" + secrets.token_hex(20))
        session.add(user)
        session.flush()
        device = Device(user_id=user.id, name="it-device")
        session.add(device)
        session.flush()
        return user, device


def key_values(device: Device, **overrides: Any) -> dict[str, Any]:
    return {
        "user_id": device.user_id,
        "device_id": device.id,
        "version": 1,
        "format": "test-format",
        "material": secrets.token_bytes(32),
        "material_digest": "sha256:" + secrets.token_hex(32),
        **overrides,
    }


def test_audit_events_are_append_only(factory: sessionmaker[Session]) -> None:
    user, device = seed(factory)
    actor = ActorContext(user_id=user.id)
    with factory() as session, session.begin():
        event = record_event(
            session, actor, AuditEventType.DEVICE_REGISTERED, owner_id=user.id, device_id=device.id
        )
        event_id = event.id
    statements = [
        text("UPDATE audit_events SET event_type = 'device.revoked' WHERE id = :id"),
        text("DELETE FROM audit_events WHERE id = :id"),
        text("TRUNCATE audit_events"),
    ]
    for statement in statements:
        with pytest.raises(DBAPIError) as caught, factory() as session, session.begin():
            session.execute(statement, {"id": event_id})
        assert "append-only" in str(caught.value.orig)
    with factory() as session:
        assert session.get(AuditEvent, event_id) is not None


def test_key_owner_must_match_device_owner(factory: sessionmaker[Session]) -> None:
    _, device = seed(factory)
    intruder, _ = seed(factory)
    with pytest.raises(IntegrityError), factory() as session, session.begin():
        session.add(PublicKey(**key_values(device, user_id=intruder.id)))


def test_single_active_key_per_device_and_format(factory: sessionmaker[Session]) -> None:
    _, device = seed(factory)
    with factory() as session, session.begin():
        session.add(PublicKey(**key_values(device, version=1)))
    with pytest.raises(IntegrityError), factory() as session, session.begin():
        session.add(PublicKey(**key_values(device, version=2)))


@pytest.mark.parametrize("label", ["Upper", "-leading-dash", "spa ce", "a" * 65, "ação"])
def test_format_label_check_is_enforced_by_postgres(
    factory: sessionmaker[Session], label: str
) -> None:
    _, device = seed(factory)
    with pytest.raises((IntegrityError, DBAPIError)), factory() as session, session.begin():
        session.add(PublicKey(**key_values(device, format=label)))


def _user_and_actor(factory: sessionmaker[Session]) -> tuple[ActorContext, str]:
    address = "0x" + secrets.token_hex(20)
    with factory() as session, session.begin():
        user, _ = register_login(session, address, datetime.now(UTC))
        return ActorContext(user_id=user.id, client={"ua": "0" * 64, "net": "1" * 64}), address


def test_concurrent_key_registrations_serialize_versions(
    factory: sessionmaker[Session],
) -> None:
    actor, address = _user_and_actor(factory)
    now = datetime.now(UTC)
    device = run_sync_transaction(
        factory, lambda s: register_device(s, actor, "concurrent", DevicePolicy(10))
    )
    # The device stays pending: registering versions does not need it to be active.
    policy = DeviceCertificatePolicy(max_bytes=8192)
    cert = new_device()
    # 12 distinct versions of the same certificate (same primary key).
    versions_material = [cert.refreshed(now + timedelta(days=100 + n)) for n in range(12)]
    proof = cert.sign(registration_statement(SERVICE, address, cert.fingerprint))

    def publish(n: int) -> int:
        def work(s: Session) -> int:
            key = register_key(
                s,
                actor,
                device.id,
                PROTOCOL_KEY_FORMAT,
                versions_material[n],
                proof,
                policy=policy,
                context=RegistrationContext(SERVICE, address, datetime.now(UTC)),
                limits=KeyLimits(100),
                recently_authenticated=True,
            )
            return key.version

        return run_sync_transaction(factory, work)

    with ThreadPoolExecutor(max_workers=8) as pool:
        versions = sorted(pool.map(publish, range(12)))
    assert versions == list(range(1, 13))
    with factory() as session:
        statuses = session.scalars(
            select(PublicKey.status).where(PublicKey.device_id == device.id)
        ).all()
    assert sorted(statuses).count("active") == 1
    assert statuses.count("superseded") == 11


def test_concurrent_device_registrations_respect_limit(factory: sessionmaker[Session]) -> None:
    actor, _address = _user_and_actor(factory)

    def attempt(i: int) -> str:
        try:
            run_sync_transaction(
                factory, lambda s: register_device(s, actor, f"d{i}", DevicePolicy(3))
            )
            return "created"
        except LimitExceededError:
            return "limited"

    with ThreadPoolExecutor(max_workers=10) as pool:
        outcomes = list(pool.map(attempt, range(10)))
    assert outcomes.count("created") == 3
    assert outcomes.count("limited") == 7


def test_device_and_directory_flow_through_the_api(settings_env: Settings) -> None:
    import base64

    from fastapi.testclient import TestClient

    from agnusmail.apps.api.main import create_app
    from tests.unit.auth_helpers import login
    from tests.unit.device_helpers import key_payload, wallet_certificate

    cert = new_device()
    with TestClient(create_app(settings_env)) as client:
        owner = login(client)
        device = client.post("/v1/devices", json={"name": "it phone"}).json()
        key = client.post(
            f"/v1/devices/{device['id']}/keys",
            json=key_payload(owner.address, cert, service=settings_env.siwe_domain),
        ).json()
        certificate = wallet_certificate(
            owner.account,
            cert.fingerprint,
            service=settings_env.siwe_domain,
            chain_id=settings_env.siwe_chain_id,
        )
        authorized = client.post(f"/v1/devices/{device['id']}/authorize", json=certificate)
        assert authorized.status_code == 200, authorized.text
        published = client.get(f"/v1/keys/{owner.address}").json()["keys"]
        assert [k["key_id"] for k in published] == [key["id"]]
        assert base64.b64decode(published[0]["material"]) == cert.material

        client.post(f"/v1/devices/{device['id']}/revoke", json={"reason": "it"})
        assert client.get(f"/v1/keys/{owner.address}").json()["keys"] == []
        events = client.get(f"/v1/devices/{device['id']}/events").json()["items"]
    assert [e["event_type"] for e in events] == [
        "device.revoked",
        "key.revoked",
        "device.authorized",
        "key.registered",
        "device.registered",
    ]
    sequences = [e["sequence"] for e in events]
    assert sequences == sorted(sequences, reverse=True)
