"""Tests for suspicious-session detection."""

import json

import pytest
from eth_account import Account
from fastapi.testclient import TestClient

from agnusmail.core.security import SESSION_COOKIE_NAME
from agnusmail.modules.authentication.suspicious import (
    Verdict,
    evaluate,
    fingerprint,
    network_of,
)
from agnusmail.testing.auth import build_message, sign
from agnusmail.testing.fakes import FakeAsyncRedis, make_app, make_settings

SESSION = "/v1/auth/session"
UA_A = {"User-Agent": "BrowserA/1.0"}
UA_B = {"User-Agent": "Curl/8.0"}


@pytest.mark.parametrize(
    ("ip", "network"),
    [
        ("203.0.113.77", "203.0.113.0/24"),
        ("2001:db8:abcd:12::1", "2001:db8:abcd::/48"),
        ("testclient", "testclient"),
    ],
)
def test_network_of(ip: str, network: str) -> None:
    assert network_of(ip) == network


def test_evaluate_rules() -> None:
    base = fingerprint("A", "203.0.113.1")
    assert evaluate(base, fingerprint("A", "203.0.113.200")) is Verdict.OK  # same /24
    assert evaluate(base, fingerprint("A", "198.51.100.1")) is Verdict.NETWORK_CHANGED
    assert evaluate(base, fingerprint("B", "203.0.113.1")) is Verdict.USER_AGENT_CHANGED
    assert evaluate({}, fingerprint("B", "198.51.100.1")) is Verdict.OK  # legacy session


def test_fingerprint_stores_only_hashes() -> None:
    fp = fingerprint("BrowserA/1.0", "203.0.113.7")
    assert all(len(value) == 64 for value in fp.values())
    assert "BrowserA" not in json.dumps(fp) and "203.0.113" not in json.dumps(fp)


def login(client: TestClient, headers: dict[str, str]) -> None:
    acct = Account.create()
    nonce = client.post("/v1/auth/siwe/nonce", headers=headers).json()["nonce"]
    response = client.post(
        "/v1/auth/siwe/verify",
        json=sign(build_message(acct.address, nonce), acct),
        headers=headers,
    )
    assert response.status_code == 200, response.text


def test_session_replayed_with_other_user_agent_is_revoked(
    capsys: pytest.CaptureFixture[str],
) -> None:
    app, _ = make_app()
    with TestClient(app, raise_server_exceptions=False) as client:
        login(client, UA_A)
        assert client.get(SESSION, headers=UA_A).status_code == 200
        replay = client.get(SESSION, headers=UA_B)
        assert replay.status_code == 401
        assert replay.json()["error"]["code"] == "SESSION_REVOKED"
        assert client.get(SESSION, headers=UA_A).status_code == 401  # revoked for good
    logs = capsys.readouterr().out
    assert '"reason": "user_agent_changed"' in logs and '"action": "revoked"' in logs


def test_user_agent_binding_can_be_disabled() -> None:
    app, _ = make_app(make_settings(session_bind_user_agent=False))
    with TestClient(app, raise_server_exceptions=False) as client:
        login(client, UA_A)
        assert client.get(SESSION, headers=UA_B).status_code == 200


def test_network_change_is_logged_once_and_not_revoked(
    capsys: pytest.CaptureFixture[str],
) -> None:
    app, fake = make_app(make_settings(trusted_proxies=["testclient"]))
    with TestClient(app, raise_server_exceptions=False) as client:
        login(client, {**UA_A, "X-Forwarded-For": "203.0.113.10"})
        capsys.readouterr()
        moved = {**UA_A, "X-Forwarded-For": "198.51.100.20"}
        assert client.get(SESSION, headers=moved).status_code == 200
        assert client.get(SESSION, headers=moved).status_code == 200
        token = client.cookies[SESSION_COOKIE_NAME]
    events = [line for line in capsys.readouterr().out.splitlines() if "session_suspicious" in line]
    assert len(events) == 1
    assert '"reason": "network_changed"' in events[0]
    assert '"action": "logged"' in events[0]
    assert "198.51.100" not in events[0]
    assert token  # session kept; TTL preserved on fingerprint update
    session_keys = [k for k in fake.store if ":data:" in k]
    assert all(key in fake.ttls for key in session_keys)


async def test_update_fingerprint_keeps_ttl_and_ignores_missing_sessions() -> None:
    from agnusmail.modules.authentication.stores import SessionStore

    fake = FakeAsyncRedis()
    store = SessionStore(fake, 60, 600, 2)
    token = await store.create("user", {}, fingerprint=fingerprint("A", "203.0.113.1"))
    new_fp = fingerprint("A", "198.51.100.1")
    await store.update_fingerprint(token, new_fp)
    record = await store.get(token)
    assert record is not None and record.fingerprint == new_fp
    assert 60 in fake.ttls.values()
    await store.update_fingerprint("missing-token", new_fp)  # no-op
    assert all(":data:" not in k or k in fake.ttls for k in fake.store)
