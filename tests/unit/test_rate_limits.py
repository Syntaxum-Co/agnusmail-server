"""Tests for per-route (login) and per-user rate limits."""

from eth_account import Account
from fastapi.testclient import TestClient

from agnusmail.testing.auth import build_message, sign
from agnusmail.testing.fakes import make_app, make_settings

NONCE = "/v1/auth/siwe/nonce"
SESSION = "/v1/auth/session"


def login(client: TestClient) -> None:
    acct = Account.create()
    nonce = client.post(NONCE).json()["nonce"]
    response = client.post(
        "/v1/auth/siwe/verify", json=sign(build_message(acct.address, nonce), acct)
    )
    assert response.status_code == 200, response.text


def test_login_routes_have_tighter_per_ip_limit() -> None:
    app, _ = make_app(make_settings(rate_limit_auth_per_ip=2))
    with TestClient(app, raise_server_exceptions=False) as client:
        statuses = [client.post(NONCE).status_code for _ in range(3)]
        other_route = client.get(SESSION)
    assert statuses == [200, 200, 429]
    assert other_route.status_code == 401  # auth bucket does not affect other routes


def test_rate_limited_login_does_not_consume_nonce() -> None:
    app, fake = make_app(make_settings(rate_limit_auth_per_ip=1))
    with TestClient(app, raise_server_exceptions=False) as client:
        acct = Account.create()
        nonce = client.post(NONCE).json()["nonce"]
        payload = sign(build_message(acct.address, nonce), acct)
        response = client.post("/v1/auth/siwe/verify", json=payload)
    assert response.status_code == 429
    assert response.json()["error"]["code"] == "RATE_LIMITED"
    assert any(key.endswith(nonce) for key in fake.store)  # rejected before nonce use


def test_authenticated_routes_are_limited_per_user() -> None:
    app, _ = make_app(make_settings(rate_limit_per_user=2))
    with (
        TestClient(app, raise_server_exceptions=False) as alice,
        TestClient(app, raise_server_exceptions=False) as bob,
    ):
        login(alice)
        login(bob)
        alice_statuses = [alice.get(SESSION).status_code for _ in range(3)]
        bob_status = bob.get(SESSION).status_code
    assert alice_statuses == [200, 200, 429]
    assert bob_status == 200  # separate per-user bucket


def test_per_user_limit_fails_open_on_backend_error() -> None:
    class BrokenLimiter:
        async def check(self, key: str, limit: int, window_seconds: int) -> bool:
            raise ConnectionError("redis down")

    app, _ = make_app()
    with TestClient(app, raise_server_exceptions=False) as client:
        login(client)
        app.state.rate_limiter = BrokenLimiter()
        assert client.get(SESSION).status_code == 200
