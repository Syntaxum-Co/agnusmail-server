"""Passkey (WebAuthn) login as an additional sign-in method."""

import time
import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_account.signers.local import LocalAccount
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.modules.audit.models import AuditEvent
from agnusmail.modules.identity.models import User, UserStatus
from agnusmail.modules.passkeys.wallet import (
    PasskeyRegistrationClaim,
    passkey_registration_typed_data,
)
from agnusmail.testing.auth import LoggedIn, login
from agnusmail.testing.fakes import make_app, make_session_factory, make_settings
from tests.webauthn_helpers import SoftAuthenticator

BASE = "/v1/auth/passkeys"


def wallet_approval(
    wallet: LocalAccount,
    credential_id: bytes,
    *,
    issued_at: int | None = None,
    service: str = "app.agnusmail",
) -> dict[str, Any]:
    issued = int(time.time()) if issued_at is None else issued_at
    claim = PasskeyRegistrationClaim(wallet.address, credential_id, service, issued)
    typed = passkey_registration_typed_data(claim, 1)
    signed = Account.sign_message(encode_typed_data(full_message=typed), private_key=wallet.key)
    return {"issued_at": issued, "signature": "0x" + bytes(signed.signature).hex()}


@pytest.fixture
def factory() -> sessionmaker[Session]:
    return make_session_factory()


@pytest.fixture
def app(factory: sessionmaker[Session]) -> Any:
    return make_app(session_factory=factory)[0]


@pytest.fixture
def client(app: Any) -> Iterator[TestClient]:
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client


@pytest.fixture
def user(client: TestClient) -> LoggedIn:
    return login(client)


def start_registration(client: TestClient) -> dict[str, Any]:
    response = client.post(f"{BASE}/registration/options")
    assert response.status_code == 200, response.text
    return response.json()  # type: ignore[no-any-return]


def register(
    client: TestClient,
    user: LoggedIn,
    authenticator: SoftAuthenticator,
    *,
    approval: dict[str, Any] | None = None,
    **create: Any,
) -> Any:
    options = start_registration(client)
    credential = authenticator.create(options, **create)
    body = {
        "name": "Laptop passkey",
        "credential": credential,
        "wallet_approval": approval or wallet_approval(user.account, authenticator.credential_id),
    }
    return client.post(f"{BASE}/registration", json=body)


def passkey_login(app: Any, authenticator: SoftAuthenticator, **get: Any) -> tuple[Any, TestClient]:
    browser = TestClient(app, raise_server_exceptions=False)
    options = browser.post(f"{BASE}/authentication/options").json()
    response = browser.post(
        f"{BASE}/authentication", json={"credential": authenticator.get(options, **get)}
    )
    return response, browser


def test_registration_options_require_a_session_and_user_verification(client: TestClient) -> None:
    assert client.post(f"{BASE}/registration/options").status_code == 401
    login(client)
    options = start_registration(client)
    assert options["rp"]["id"] == "app.agnusmail"
    assert options["authenticatorSelection"]["userVerification"] == "required"
    assert options["authenticatorSelection"]["residentKey"] == "required"


def test_register_and_log_in_with_a_passkey(
    app: Any, client: TestClient, user: LoggedIn, factory: sessionmaker[Session]
) -> None:
    authenticator = SoftAuthenticator()
    response = register(client, user, authenticator)
    assert response.status_code == 201, response.text
    assert response.json()["status"] == "active" and response.json()["backed_up"] is False
    assert [p["name"] for p in client.get(BASE).json()["items"]] == ["Laptop passkey"]

    logged, browser = passkey_login(app, authenticator)
    with browser:
        assert logged.status_code == 200, logged.text
        assert logged.json()["user_id"] == user.user_id
        session = browser.get("/v1/auth/session").json()
    assert session["auth_method"] == "passkey"
    assert session["address"] == user.address  # same account as the wallet login
    with factory() as db:
        kinds = db.scalars(
            select(AuditEvent.event_type)
            .where(AuditEvent.user_id == uuid.UUID(user.user_id))
            .order_by(AuditEvent.chain_seq)
        ).all()
        last_login = db.scalars(
            select(AuditEvent)
            .where(AuditEvent.event_type == "auth.login")
            .order_by(AuditEvent.chain_seq.desc())
        ).first()
    assert kinds == ["auth.login", "auth.passkey_registered", "auth.login"]
    assert last_login is not None and last_login.details["method"] == "passkey"


def test_wallet_approval_is_mandatory(client: TestClient, user: LoggedIn) -> None:
    authenticator = SoftAuthenticator()
    stranger = Account.create()
    cases = [
        wallet_approval(stranger, authenticator.credential_id),  # not the account's wallet
        wallet_approval(user.account, b"other credential"),  # approves another passkey
        wallet_approval(user.account, authenticator.credential_id, service="evil.example"),
        wallet_approval(
            user.account, authenticator.credential_id, issued_at=int(time.time()) - 3600
        ),
    ]
    for approval in cases:
        response = register(client, user, authenticator, approval=approval)
        assert response.status_code == 422, approval
        assert response.json()["error"]["code"] == "ATTESTATION_REJECTED"
    assert client.get(BASE).json()["items"] == []


@pytest.mark.parametrize(
    "create",
    [
        {"user_verified": False},  # no PIN/biometric
        {"origin": "https://phishing.example"},  # created on another site
        {"rp_id": "phishing.example"},
    ],
)
def test_invalid_registrations_are_rejected(
    client: TestClient, user: LoggedIn, create: dict[str, Any]
) -> None:
    response = register(client, user, SoftAuthenticator(), **create)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "PASSKEY_REGISTRATION_REJECTED"


def test_registration_challenge_is_single_use(client: TestClient, user: LoggedIn) -> None:
    authenticator = SoftAuthenticator()
    options = start_registration(client)
    body = {
        "name": "Key",
        "credential": authenticator.create(options),
        "wallet_approval": wallet_approval(user.account, authenticator.credential_id),
    }
    assert client.post(f"{BASE}/registration", json=body).status_code == 201
    assert client.post(f"{BASE}/registration", json=body).status_code == 422


def test_login_rejections_look_the_same(app: Any, client: TestClient, user: LoggedIn) -> None:
    authenticator = SoftAuthenticator()
    register(client, user, authenticator)
    unknown = SoftAuthenticator()
    attempts = [
        passkey_login(app, unknown)[0],  # never registered
        passkey_login(app, authenticator, user_verified=False)[0],
        passkey_login(app, authenticator, origin="https://phishing.example")[0],
    ]
    for response in attempts:
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "PASSKEY_REJECTED"


def test_assertions_cannot_be_replayed_and_clones_are_caught(
    app: Any, client: TestClient, user: LoggedIn
) -> None:
    authenticator = SoftAuthenticator()
    register(client, user, authenticator)
    browser = TestClient(app, raise_server_exceptions=False)
    options = browser.post(f"{BASE}/authentication/options").json()
    assertion = authenticator.get(options)
    assert browser.post(f"{BASE}/authentication", json={"credential": assertion}).status_code == 200
    replay = browser.post(f"{BASE}/authentication", json={"credential": assertion})
    assert replay.status_code == 401  # challenge already used

    # A cloned authenticator would present a counter that does not move forward.
    response, _ = passkey_login(app, authenticator, counter_step=0)
    assert response.status_code == 401


def test_suspended_account_cannot_log_in_with_a_passkey(
    app: Any, client: TestClient, user: LoggedIn, factory: sessionmaker[Session]
) -> None:
    authenticator = SoftAuthenticator()
    register(client, user, authenticator)
    with factory() as db, db.begin():
        account = db.get(User, uuid.UUID(user.user_id))
        assert account is not None
        account.status = UserStatus.SUSPENDED
    response, _ = passkey_login(app, authenticator)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "ACCOUNT_SUSPENDED"


def test_revoking_a_passkey_ends_its_sessions(app: Any, client: TestClient, user: LoggedIn) -> None:
    authenticator = SoftAuthenticator()
    passkey_id = register(client, user, authenticator).json()["id"]
    _, browser = passkey_login(app, authenticator)
    assert browser.get("/v1/auth/session").status_code == 200

    revoked = client.post(f"{BASE}/{passkey_id}/revoke")
    assert revoked.status_code == 200 and revoked.json()["status"] == "revoked"
    assert browser.get("/v1/auth/session").status_code == 401  # passkey session ended
    assert client.get("/v1/auth/session").status_code == 200  # wallet session untouched
    response, _ = passkey_login(app, authenticator)
    assert response.status_code == 401
    assert client.post(f"{BASE}/{passkey_id}/revoke").status_code == 409


def test_passkeys_are_private_to_their_account(
    app: Any, client: TestClient, user: LoggedIn
) -> None:
    passkey_id = register(client, user, SoftAuthenticator()).json()["id"]
    with TestClient(app, raise_server_exceptions=False) as other:
        login(other)
        assert other.get(BASE).json()["items"] == []
        assert other.post(f"{BASE}/{passkey_id}/revoke").status_code == 404


def test_passkey_limit_and_duplicates() -> None:
    app, _ = make_app(make_settings(max_passkeys_per_user=1))
    with TestClient(app, raise_server_exceptions=False) as client:
        user = login(client)
        authenticator = SoftAuthenticator()
        assert register(client, user, authenticator).status_code == 201
        blocked = register(client, user, SoftAuthenticator())
        assert blocked.status_code == 409 and blocked.json()["error"]["code"] == "LIMIT_EXCEEDED"


def test_passkey_login_counts_as_a_recent_login(
    app: Any, client: TestClient, user: LoggedIn
) -> None:
    """Step-up actions (e.g. claiming the address) accept a fresh passkey login."""
    authenticator = SoftAuthenticator()
    register(client, user, authenticator)
    _, browser = passkey_login(app, authenticator)
    with browser:
        response = browser.post("/v1/addresses", json={"local_part": "passkeyuser"})
    assert response.status_code == 201, response.text


def test_prf_output_is_refused_and_never_echoed(
    app: Any, client: TestClient, user: LoggedIn
) -> None:
    """The PRF output unlocks the device key locally; a client must strip it."""
    authenticator = SoftAuthenticator()
    secret = "c2VjcmV0LXByZi1vdXRwdXQ"
    leaked = {"prf": {"enabled": True, "results": {"first": secret}}}

    options = start_registration(client)
    credential = authenticator.create(options) | {"clientExtensionResults": leaked}
    body = {
        "name": "Laptop passkey",
        "credential": credential,
        "wallet_approval": wallet_approval(user.account, authenticator.credential_id),
    }
    refused = client.post(f"{BASE}/registration", json=body)
    assert refused.status_code == 422 and secret not in refused.text

    assert register(client, user, authenticator).status_code == 201
    browser = TestClient(app, raise_server_exceptions=False)
    options = browser.post(f"{BASE}/authentication/options").json()
    assertion = authenticator.get(options) | {"clientExtensionResults": leaked}
    response = browser.post(f"{BASE}/authentication", json={"credential": assertion})
    assert response.status_code == 422 and secret not in response.text
    # The single-prompt flow: login and unlock together. The authenticator's signed
    # hmac-secret output is opaque to the server (encrypted to the browser), and the
    # client strips the PRF result before sending.
    ok, _ = passkey_login(app, authenticator, extensions={"hmac-secret": bytes(48)})
    assert ok.status_code == 200, ok.text
