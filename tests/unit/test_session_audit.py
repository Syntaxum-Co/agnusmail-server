"""Login, logout and session revocations are audited in the user's chain (DV-05)."""

import json
import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from eth_account import Account
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.modules.audit.integrity import verify_user_chain
from agnusmail.modules.audit.models import AuditEvent
from agnusmail.modules.identity.models import User, UserStatus
from agnusmail.testing.auth import build_message, sign
from agnusmail.testing.fakes import make_app, make_session_factory

UA_A = {"User-Agent": "BrowserA/1.0"}
UA_B = {"User-Agent": "Curl/8.0"}


@pytest.fixture
def factory() -> sessionmaker[Session]:
    return make_session_factory()


@pytest.fixture
def client(factory: sessionmaker[Session]) -> Iterator[TestClient]:
    app, _ = make_app(session_factory=factory)
    with TestClient(app, raise_server_exceptions=False, headers=UA_A) as test_client:
        yield test_client


def login(client: TestClient, acct: Any = None) -> tuple[str, Any]:
    acct = acct or Account.create()
    nonce = client.post("/v1/auth/siwe/nonce").json()["nonce"]
    response = client.post(
        "/v1/auth/siwe/verify", json=sign(build_message(acct.address, nonce), acct)
    )
    assert response.status_code == 200, response.text
    return response.json()["user_id"], acct


def events(factory: sessionmaker[Session], user_id: str) -> list[AuditEvent]:
    with factory() as session:
        rows = session.scalars(
            select(AuditEvent)
            .where(AuditEvent.user_id == uuid.UUID(user_id))
            .order_by(AuditEvent.chain_seq)
        ).all()
        return list(rows)


def kinds(factory: sessionmaker[Session], user_id: str) -> list[str]:
    return [e.event_type for e in events(factory, user_id)]


def test_login_and_logout_share_the_public_session_id(
    client: TestClient, factory: sessionmaker[Session]
) -> None:
    user_id, _ = login(client)
    session_id = client.get("/v1/auth/session").json()["session_id"]
    assert client.post("/v1/auth/logout").status_code == 200
    assert client.post("/v1/auth/logout").status_code == 200  # idempotent, no 2nd event

    logged = events(factory, user_id)
    assert [e.event_type for e in logged] == ["auth.login", "auth.logout"]
    for event in logged:
        assert event.actor_user_id == uuid.UUID(user_id)
        assert event.details["session"] == session_id
        assert set(event.details["client"]) == {"ua", "net"}  # hashes only
    serialized = json.dumps([e.details for e in logged])
    assert "BrowserA" not in serialized and "testclient" not in serialized
    with factory() as session:
        assert verify_user_chain(session, uuid.UUID(user_id)).ok


def test_suspended_account_login_is_audited_as_denied(factory: sessionmaker[Session]) -> None:
    acct = Account.create()
    with factory() as session, session.begin():
        user = User(ethereum_address=acct.address.lower(), status=UserStatus.SUSPENDED)
        session.add(user)
        session.flush()
        user_id = str(user.id)
    app, _ = make_app(session_factory=factory)
    with TestClient(app, raise_server_exceptions=False) as client:
        nonce = client.post("/v1/auth/siwe/nonce").json()["nonce"]
        response = client.post(
            "/v1/auth/siwe/verify", json=sign(build_message(acct.address, nonce), acct)
        )
    assert response.status_code == 403
    denied = events(factory, user_id)
    assert [e.event_type for e in denied] == ["auth.login_denied"]
    assert denied[0].details["reason"] == "account_suspended"


def test_new_login_audits_the_replaced_session(
    client: TestClient, factory: sessionmaker[Session]
) -> None:
    user_id, acct = login(client)
    first_session = client.get("/v1/auth/session").json()["session_id"]
    login(client, acct)  # the old cookie is still in the jar
    second_session = client.get("/v1/auth/session").json()["session_id"]

    logged = events(factory, user_id)
    assert [e.event_type for e in logged] == [
        "auth.login",
        "auth.login",
        "auth.session_revoked",
    ]
    assert logged[2].details["session"] == first_session
    assert logged[2].details["reason"] == "replaced_by_login"
    assert logged[1].details["session"] == second_session != first_session


def test_suspicious_revocation_is_a_system_event(
    client: TestClient, factory: sessionmaker[Session]
) -> None:
    user_id, _ = login(client)
    session_id = client.get("/v1/auth/session").json()["session_id"]
    replay = client.get("/v1/auth/session", headers=UA_B)
    assert replay.status_code == 401

    revoked = events(factory, user_id)[-1]
    assert revoked.event_type == "auth.session_revoked"
    assert revoked.actor_user_id is None
    assert revoked.details["reason"] == "user_agent_changed"
    assert revoked.details["session"] == session_id
    assert set(revoked.details["observed_client"]) == {"ua", "net"}
    assert "Curl" not in json.dumps(revoked.details)


def test_logout_succeeds_even_if_the_audit_write_fails(
    client: TestClient, factory: sessionmaker[Session]
) -> None:
    user_id, _ = login(client)

    def broken() -> Session:
        raise RuntimeError("database down")

    client.app.state.db_session_factory = broken  # type: ignore[attr-defined]
    response = client.post("/v1/auth/logout")
    assert response.status_code == 200
    assert "Max-Age=0" in response.headers["set-cookie"] or "expires" in (
        response.headers["set-cookie"].lower()
    )
    client.app.state.db_session_factory = factory  # type: ignore[attr-defined]
    assert client.get("/v1/auth/session").status_code == 401  # session really revoked
    assert kinds(factory, user_id) == ["auth.login"]  # the failure is logged, not hidden
