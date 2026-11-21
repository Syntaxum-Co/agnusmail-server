"""Tests for the session renewal endpoint."""

from eth_account import Account
from fastapi.testclient import TestClient

from agnusmail.core.security import SESSION_COOKIE_NAME
from agnusmail.testing.auth import build_message, sign
from agnusmail.testing.fakes import make_app


def test_renew_without_cookie_is_401() -> None:
    app, _ = make_app()
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.post("/v1/auth/renew")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "NO_SESSION"


def test_renew_with_unknown_session_is_401() -> None:
    app, _ = make_app()
    with TestClient(app, raise_server_exceptions=False) as client:
        client.cookies.set(SESSION_COOKIE_NAME, "unknown-token")
        response = client.post("/v1/auth/renew")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "NO_SESSION"


def test_renew_valid_session_refreshes_cookie() -> None:
    app, _ = make_app()
    with TestClient(app, raise_server_exceptions=False) as client:
        acct = Account.create()
        nonce = client.post("/v1/auth/siwe/nonce").json()["nonce"]
        client.post("/v1/auth/siwe/verify", json=sign(build_message(acct.address, nonce), acct))
        response = client.post("/v1/auth/renew")
    assert response.status_code == 200
    assert response.json() == {"renewed": True, "expires_in": 86400}
    assert "Max-Age=86400" in response.headers["set-cookie"]
