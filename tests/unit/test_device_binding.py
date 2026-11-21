"""Sessions bound to devices (4.D.5, protocol v1 §5)."""

import asyncio
import base64
import uuid
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.modules.audit.models import AuditEvent
from agnusmail.modules.authentication.device_binding import revoke_sessions_of
from agnusmail.modules.authentication.stores import DEVICE_CHALLENGE_PREFIX
from agnusmail.modules.devices.models import Device, DeviceStatus
from tests.openpgp_helpers import DeviceKeys, new_device
from tests.unit.auth_helpers import LoggedIn, login
from tests.unit.device_helpers import DEVICES, Onboarded, onboard
from tests.unit.fakes import FakeAsyncRedis, make_app, make_session_factory

CHALLENGE = "/v1/auth/device/challenge"
BIND = "/v1/auth/device/bind"
CURRENT = "/v1/auth/device"


@pytest.fixture
def factory() -> sessionmaker[Session]:
    return make_session_factory()


@pytest.fixture
def app_and_redis(factory: sessionmaker[Session]) -> tuple[object, FakeAsyncRedis]:
    return make_app(session_factory=factory)


@pytest.fixture
def client(app_and_redis: tuple[object, FakeAsyncRedis]) -> Iterator[TestClient]:
    with TestClient(app_and_redis[0], raise_server_exceptions=False) as test_client:  # type: ignore[arg-type]
        yield test_client


@pytest.fixture
def user(client: TestClient) -> LoggedIn:
    return login(client)


def challenge(client: TestClient, device_id: str) -> dict[str, object]:
    response = client.post(CHALLENGE, json={"device_id": device_id})
    assert response.status_code == 200, response.text
    return response.json()  # type: ignore[no-any-return]


def bind(client: TestClient, device_id: str, keys: DeviceKeys, statement: str) -> int:
    signature = base64.b64encode(keys.sign(statement.encode("ascii"))).decode()
    response = client.post(BIND, json={"device_id": device_id, "signature": signature})
    return response.status_code


def bound(client: TestClient, user: LoggedIn) -> Onboarded:
    device = onboard(client, user)
    issued = challenge(client, device.device_id)
    assert bind(client, device.device_id, device.keys, str(issued["statement"])) == 200
    return device


def test_full_binding_flow(
    client: TestClient, user: LoggedIn, factory: sessionmaker[Session]
) -> None:
    device = onboard(client, user)
    assert client.get(CURRENT).json()["error"]["code"] == "DEVICE_SESSION_REQUIRED"

    issued = challenge(client, device.device_id)
    assert issued["expires_in"] == 120
    assert issued["statement"] == (
        f"agnusmail/device-session/v1\napp.agnusmail\n{device.keys.fingerprint}\n"
        f"{issued['challenge']}"
    )
    assert len(str(issued["challenge"])) == 64
    assert bind(client, device.device_id, device.keys, str(issued["statement"])) == 200

    current = client.get(CURRENT)
    assert current.status_code == 200
    assert current.json() == {"device_id": device.device_id, "fingerprint": device.keys.fingerprint}
    with factory() as session:
        event = session.scalars(
            select(AuditEvent).where(AuditEvent.event_type == "auth.session_bound")
        ).one()
        assert str(event.device_id) == device.device_id
        assert event.details["session"] == client.get("/v1/auth/session").json()["session_id"]


def test_challenges_are_single_use(client: TestClient, user: LoggedIn) -> None:
    device = onboard(client, user)
    statement = str(challenge(client, device.device_id)["statement"])
    assert bind(client, device.device_id, device.keys, statement) == 200
    assert bind(client, device.device_id, device.keys, statement) == 401  # replay


def test_expired_challenge_is_refused(
    client: TestClient, user: LoggedIn, app_and_redis: tuple[object, FakeAsyncRedis]
) -> None:
    device = onboard(client, user)
    statement = str(challenge(client, device.device_id)["statement"])
    redis = app_and_redis[1]
    for key in [k for k in redis.store if k.startswith(DEVICE_CHALLENGE_PREFIX)]:
        redis.expire_now(key)
    assert bind(client, device.device_id, device.keys, statement) == 401


def test_wrong_proofs_are_refused(client: TestClient, user: LoggedIn) -> None:
    device = onboard(client, user)
    other = onboard(client, user)
    cases = []
    statement = str(challenge(client, device.device_id)["statement"])
    cases.append(bind(client, device.device_id, new_device(), statement))  # foreign key
    statement = str(challenge(client, device.device_id)["statement"])
    cases.append(bind(client, device.device_id, device.keys, statement + "x"))  # other text
    statement = str(challenge(client, device.device_id)["statement"])
    cases.append(bind(client, other.device_id, other.keys, statement))  # other device id
    assert cases == [401, 401, 401]
    assert client.get(CURRENT).status_code == 403


def test_only_own_active_devices_can_be_bound(client: TestClient, user: LoggedIn) -> None:
    pending = onboard(client, user, authorize=False)
    response = client.post(CHALLENGE, json={"device_id": pending.device_id})
    assert response.status_code == 409
    assert client.post(CHALLENGE, json={"device_id": str(uuid.uuid4())}).status_code == 404
    with TestClient(client.app, raise_server_exceptions=False) as intruder:
        login(intruder)
        mine = onboard(client, user)
        assert intruder.post(CHALLENGE, json={"device_id": mine.device_id}).status_code == 404


def test_revoking_a_device_ends_only_its_sessions(client: TestClient, user: LoggedIn) -> None:
    device = bound(client, user)
    with TestClient(client.app, raise_server_exceptions=False) as second:
        login(second, user.account)  # same account, session not bound to the device
        response = second.post(f"{DEVICES}/{device.device_id}/revoke", json={})
        assert response.status_code == 200
        assert second.get("/v1/auth/session").status_code == 200
    assert client.get("/v1/auth/session").status_code == 401


def test_database_check_catches_a_missed_revocation(
    client: TestClient, user: LoggedIn, factory: sessionmaker[Session]
) -> None:
    """If the Redis index revocation failed, the per-request check still ends it."""
    device = bound(client, user)
    with factory() as session, session.begin():
        row = session.get(Device, uuid.UUID(device.device_id))
        assert row is not None
        row.status = DeviceStatus.REVOKED
        row.revoked_at = row.created_at
    response = client.get(CURRENT)
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "SESSION_REVOKED"
    assert client.get("/v1/auth/session").status_code == 401


def test_session_revocation_failure_is_logged_not_raised(
    capsys: pytest.CaptureFixture[str],
) -> None:
    class BrokenStore:
        async def revoke_device_sessions(self, _device_id: str) -> int:
            raise ConnectionError("redis down")

    class FakeRequest:
        class app:  # noqa: N801  (attribute bag)
            class state:  # noqa: N801
                session_store = BrokenStore()

    asyncio.run(revoke_sessions_of(FakeRequest(), uuid.uuid4()))  # type: ignore[arg-type]
    assert "device_sessions_revoke_failed" in capsys.readouterr().out


@pytest.mark.parametrize(
    "payload",
    [
        {"device_id": "not-a-uuid", "signature": "AA=="},
        {"device_id": str(uuid.uuid4()), "signature": "***"},
        {"device_id": str(uuid.uuid4())},
        {"device_id": str(uuid.uuid4()), "signature": "AA==", "extra": 1},
    ],
)
def test_bind_payload_validation(
    client: TestClient, user: LoggedIn, payload: dict[str, object]
) -> None:
    assert client.post(BIND, json=payload).status_code == 422


def test_binding_requires_a_session(client: TestClient) -> None:
    assert client.post(CHALLENGE, json={"device_id": str(uuid.uuid4())}).status_code == 401
    assert client.get(CURRENT).status_code == 401
