"""Tests for CSRF protection."""

import pytest
from agnusmail.apps.api.middleware.csrf import origin_of, trusted_origins
from fastapi.testclient import TestClient

from agnusmail.core.config import Settings
from tests.unit.fakes import make_app, make_settings

NONCE = "/v1/auth/siwe/nonce"


def client_for(**overrides: object) -> TestClient:
    app, _ = make_app(make_settings(**overrides))
    return TestClient(app, raise_server_exceptions=False)


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://App.Example/login", "https://app.example"),
        ("https://app.example:443/x", "https://app.example"),
        ("http://localhost:3000/", "http://localhost:3000"),
        ("not a url", None),
    ],
)
def test_origin_of(url: str, expected: str | None) -> None:
    assert origin_of(url) == expected


def test_trusted_origins_include_cors_and_frontend() -> None:
    settings: Settings = make_settings(cors_allowed_origins=["https://web.example"])
    assert trusted_origins(settings) == {"https://web.example", "https://app.agnusmail"}


@pytest.mark.parametrize(
    "headers",
    [
        {"Origin": "https://evil.example"},
        {"Origin": "null"},
        {"Origin": "https://app.agnusmail.evil.example"},
        {"Sec-Fetch-Site": "cross-site"},
    ],
)
def test_cross_site_unsafe_requests_are_rejected(headers: dict[str, str]) -> None:
    with client_for() as client:
        response = client.post(NONCE, headers=headers)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "CSRF_REJECTED"
    assert response.headers["X-Content-Type-Options"] == "nosniff"


@pytest.mark.parametrize(
    "headers",
    [
        {},  # non-browser client
        {"Origin": "http://testserver"},  # same origin as the API
        {"Origin": "https://app.agnusmail"},  # frontend (origin of siwe_uri)
        {"Origin": "https://web.example", "Sec-Fetch-Site": "cross-site"},  # CORS allowlist
        {"Sec-Fetch-Site": "same-origin"},
    ],
)
def test_trusted_unsafe_requests_pass(headers: dict[str, str]) -> None:
    with client_for(cors_allowed_origins=["https://web.example"]) as client:
        assert client.post(NONCE, headers=headers).status_code == 200


def test_safe_methods_are_not_checked() -> None:
    with client_for() as client:
        response = client.get("/v1/auth/session", headers={"Origin": "https://evil.example"})
    assert response.status_code == 401  # reached the handler (no session)


def test_logout_csrf_does_not_revoke_session() -> None:
    from eth_account import Account

    from tests.unit.test_auth import build_message, sign

    with client_for() as client:
        acct = Account.create()
        nonce = client.post(NONCE).json()["nonce"]
        client.post("/v1/auth/siwe/verify", json=sign(build_message(acct.address, nonce), acct))
        forged = client.post("/v1/auth/logout", headers={"Origin": "https://evil.example"})
        assert forged.status_code == 403
        assert client.get("/v1/auth/session").status_code == 200
