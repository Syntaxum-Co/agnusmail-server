"""Tests for SIWE login and the session lifecycle over HTTP, with a fake Redis."""

import hashlib
from datetime import UTC, datetime, timedelta

from eth_account import Account
from fastapi.testclient import TestClient

from agnusmail.core.security import SESSION_COOKIE_NAME
from agnusmail.modules.authentication.stores import SESSION_DATA_PREFIX
from agnusmail.testing.auth import build_message, sign
from agnusmail.testing.fakes import FakeAsyncRedis, make_app


def login_payload(client: TestClient, **kwargs: object) -> tuple[dict[str, str], str]:
    acct = Account.create()
    nonce = client.post("/v1/auth/siwe/nonce").json()["nonce"]
    message = build_message(acct.address, nonce, **kwargs)  # type: ignore[arg-type]
    return sign(message, acct), acct.address


def client_and_redis() -> tuple[TestClient, FakeAsyncRedis]:
    app, fake = make_app()
    return TestClient(app, raise_server_exceptions=False), fake


def test_nonce_is_random() -> None:
    client, _ = client_and_redis()
    with client:
        n1 = client.post("/v1/auth/siwe/nonce").json()["nonce"]
        n2 = client.post("/v1/auth/siwe/nonce").json()["nonce"]
    assert n1 != n2
    assert len(n1) == 32


def test_siwe_verify_creates_session_cookie() -> None:
    client, _ = client_and_redis()
    with client:
        payload, address = login_payload(client)
        response = client.post("/v1/auth/siwe/verify", json=payload)
        assert response.status_code == 200
        assert response.json()["authenticated"] is True
        assert SESSION_COOKIE_NAME in response.cookies
        assert client.get("/v1/auth/session").json()["address"] == address


def test_session_token_is_stored_hashed() -> None:
    client, fake = client_and_redis()
    with client:
        payload, _ = login_payload(client)
        token = client.post("/v1/auth/siwe/verify", json=payload).cookies[SESSION_COOKIE_NAME]
    digest = hashlib.sha256(token.encode()).hexdigest()
    assert SESSION_DATA_PREFIX + digest in fake.store
    assert all(token not in key and token not in value for key, value in fake.store.items())


def test_nonce_cannot_be_replayed() -> None:
    client, _ = client_and_redis()
    with client:
        payload, _ = login_payload(client)
        assert client.post("/v1/auth/siwe/verify", json=payload).status_code == 200
        replay = client.post("/v1/auth/siwe/verify", json=payload)
    assert replay.status_code == 401
    assert replay.json()["error"]["detail"] == "nonce unknown or already used"


def test_siwe_verify_rejects_bad_signature() -> None:
    client, _ = client_and_redis()
    with client:
        payload, _ = login_payload(client)
        payload["signature"] = "0x" + "00" * 65
        response = client.post("/v1/auth/siwe/verify", json=payload)
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "SIWE_VERIFICATION_FAILED"


def test_failed_verification_does_not_burn_nonce() -> None:
    client, fake = client_and_redis()
    with client:
        payload, _ = login_payload(client)
        good_signature = payload["signature"]
        payload["signature"] = "0x" + "00" * 65
        assert client.post("/v1/auth/siwe/verify", json=payload).status_code == 401
        payload["signature"] = good_signature
        assert client.post("/v1/auth/siwe/verify", json=payload).status_code == 200


def test_siwe_verify_rejects_unknown_nonce() -> None:
    client, _ = client_and_redis()
    acct = Account.create()
    payload = sign(build_message(acct.address, "f8ea3f016a0dc2b3a6d5c9e0b7a1d2c4"), acct)
    with client:
        response = client.post("/v1/auth/siwe/verify", json=payload)
    assert response.status_code == 401
    assert response.json()["error"]["detail"] == "nonce unknown or already used"


def test_siwe_verify_rejects_wrong_signer() -> None:
    client, _ = client_and_redis()
    with client:
        payload, _ = login_payload(client)
        other = Account.create()
        payload["signature"] = sign(payload["message"], other)["signature"]
        response = client.post("/v1/auth/siwe/verify", json=payload)
    assert response.status_code == 401
    assert response.json()["error"]["detail"] == "signature does not match address"


def test_siwe_verify_rejects_wrong_domain() -> None:
    client, _ = client_and_redis()
    with client:
        payload, _ = login_payload(client, domain="wrong.example")
        response = client.post("/v1/auth/siwe/verify", json=payload)
    assert response.status_code == 401
    assert response.json()["error"]["detail"] == "domain mismatch"


def test_siwe_verify_rejects_expired_message() -> None:
    client, _ = client_and_redis()
    issued = datetime.now(UTC) - timedelta(minutes=20)
    with client:
        payload, _ = login_payload(client, issued=issued, expiration=issued + timedelta(minutes=10))
        response = client.post("/v1/auth/siwe/verify", json=payload)
    assert response.status_code == 401
    assert response.json()["error"]["detail"] == "message expired"


def test_siwe_verify_rejects_message_issued_in_future() -> None:
    client, _ = client_and_redis()
    with client:
        payload, _ = login_payload(client, issued=datetime.now(UTC) + timedelta(hours=1))
        response = client.post("/v1/auth/siwe/verify", json=payload)
    assert response.status_code == 401
    assert response.json()["error"]["detail"] == "message issued in the future"


def test_siwe_verify_non_numeric_chain_id_is_401_not_500() -> None:
    client, _ = client_and_redis()
    with client:
        payload, _ = login_payload(client, chain_id="abc")
        response = client.post("/v1/auth/siwe/verify", json=payload)
    assert response.status_code == 401
    assert response.json()["error"]["detail"] == "invalid chain id"


def test_siwe_verify_accepts_fractional_second_timestamps() -> None:
    client, _ = client_and_redis()
    with client:
        payload, _ = login_payload(client, timestamp_format="%Y-%m-%dT%H:%M:%S.000Z")
        response = client.post("/v1/auth/siwe/verify", json=payload)
    assert response.status_code == 200


def test_siwe_verify_rejects_malformed_payload() -> None:
    client, _ = client_and_redis()
    with client:
        bad_signature = client.post(
            "/v1/auth/siwe/verify", json={"message": "x", "signature": "not-hex"}
        )
        extra_field = client.post(
            "/v1/auth/siwe/verify",
            json={"message": "x", "signature": "00" * 65, "admin": True},
        )
        too_long = client.post(
            "/v1/auth/siwe/verify", json={"message": "x" * 5000, "signature": "00" * 65}
        )
    assert bad_signature.status_code == 422
    assert extra_field.status_code == 422
    assert too_long.status_code == 422


def test_logout_revokes_session() -> None:
    client, _ = client_and_redis()
    with client:
        payload, _ = login_payload(client)
        client.post("/v1/auth/siwe/verify", json=payload)
        assert client.get("/v1/auth/session").status_code == 200
        assert client.post("/v1/auth/logout").status_code == 200
        assert client.get("/v1/auth/session").status_code == 401


def test_new_login_revokes_previous_cookie_session() -> None:
    client, _ = client_and_redis()
    with client:
        payload, _ = login_payload(client)
        first = client.post("/v1/auth/siwe/verify", json=payload).cookies[SESSION_COOKIE_NAME]
        payload, _ = login_payload(client)
        second = client.post("/v1/auth/siwe/verify", json=payload).cookies[SESSION_COOKIE_NAME]
        assert first != second
        client.cookies.clear()
        client.cookies.set(SESSION_COOKIE_NAME, first)
        assert client.get("/v1/auth/session").status_code == 401


def test_session_without_cookie_is_401() -> None:
    client, _ = client_and_redis()
    with client:
        assert client.get("/v1/auth/session").status_code == 401


def test_expired_session_is_401() -> None:
    client, fake = client_and_redis()
    with client:
        payload, _ = login_payload(client)
        token = client.post("/v1/auth/siwe/verify", json=payload).cookies[SESSION_COOKIE_NAME]
        fake.expire_now(SESSION_DATA_PREFIX + hashlib.sha256(token.encode()).hexdigest())
        assert client.get("/v1/auth/session").status_code == 401
