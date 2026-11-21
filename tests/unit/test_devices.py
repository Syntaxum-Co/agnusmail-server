"""Device management API (entrega B): register, list, authorize, revoke, history."""

import time
from collections.abc import Iterator
from typing import Any

import pytest
from eth_account import Account
from fastapi.testclient import TestClient

from agnusmail.modules.authentication import dependencies
from tests.openpgp_helpers import DeviceKeys, new_device
from tests.unit.auth_helpers import LoggedIn, login
from tests.unit.device_helpers import add_key, wallet_certificate, wallet_revocation
from tests.unit.fakes import make_app, make_settings

DEVICES = "/v1/devices"
UA = {"User-Agent": "AgnusTest/1.0"}


@pytest.fixture
def client() -> Iterator[TestClient]:
    app, _ = make_app()
    with TestClient(app, raise_server_exceptions=False, headers=UA) as test_client:
        yield test_client


@pytest.fixture
def user(client: TestClient) -> LoggedIn:
    return login(client)


def register(client: TestClient, name: str = "laptop") -> dict[str, object]:
    response = client.post(DEVICES, json={"name": name})
    assert response.status_code == 201, response.text
    return response.json()  # type: ignore[no-any-return]


def test_register_creates_pending_device(client: TestClient, user: LoggedIn) -> None:
    device = register(client, "Natan's phone 📱")
    assert device["status"] == "pending"
    assert device["name"] == "Natan's phone 📱"
    assert device["authorized_at"] is None and device["revoked_at"] is None
    assert client.get(f"{DEVICES}/{device['id']}").json() == device


@pytest.mark.parametrize(
    "payload",
    [
        {"name": ""},
        {"name": "x" * 65},
        {"name": " leading"},
        {"name": "trailing "},
        {"name": "bell\x07"},
        {"name": "rtl‮override"},
        {"name": "zero​width"},
        {"name": 123},
        {"name": "ok", "status": "active"},  # mass assignment
        {},
    ],
)
def test_register_rejects_invalid_payloads(
    client: TestClient, user: LoggedIn, payload: dict[str, object]
) -> None:
    response = client.post(DEVICES, json=payload)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_device_limit_counts_only_open_devices() -> None:
    app, _ = make_app(make_settings(max_devices_per_user=2))
    with TestClient(app, raise_server_exceptions=False, headers=UA) as client:
        login(client)
        first = register(client, "one")
        register(client, "two")
        blocked = client.post(DEVICES, json={"name": "three"})
        assert blocked.status_code == 409
        assert blocked.json()["error"]["code"] == "LIMIT_EXCEEDED"
        client.post(f"{DEVICES}/{first['id']}/revoke", json={})
        assert client.post(DEVICES, json={"name": "three"}).status_code == 201


def test_list_paginates_filters_and_orders_newest_first(client: TestClient, user: LoggedIn) -> None:
    ids = [register(client, f"device {i}")["id"] for i in range(3)]
    client.post(f"{DEVICES}/{ids[0]}/revoke", json={})

    page = client.get(DEVICES, params={"limit": 2}).json()
    assert page["total"] == 3 and page["limit"] == 2 and page["offset"] == 0
    assert [d["id"] for d in page["items"]] == [ids[2], ids[1]]
    rest = client.get(DEVICES, params={"limit": 2, "offset": 2}).json()
    assert [d["id"] for d in rest["items"]] == [ids[0]]

    pending = client.get(DEVICES, params={"status": "pending"}).json()
    assert pending["total"] == 2
    assert {d["status"] for d in pending["items"]} == {"pending"}


@pytest.mark.parametrize(
    "params", [{"limit": 0}, {"limit": 101}, {"offset": -1}, {"status": "deleted"}]
)
def test_list_rejects_invalid_query(
    client: TestClient, user: LoggedIn, params: dict[str, str | int]
) -> None:
    assert client.get(DEVICES, params=params).status_code == 422


def test_get_unknown_or_malformed_device(client: TestClient, user: LoggedIn) -> None:
    missing = client.get(f"{DEVICES}/00000000-0000-4000-8000-000000000000")
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "NOT_FOUND"
    assert client.get(f"{DEVICES}/not-a-uuid").status_code == 422


def with_certificate(client: TestClient, user: LoggedIn) -> tuple[dict[str, Any], DeviceKeys]:
    """A pending device that already published its OpenPGP certificate."""
    keys = new_device()
    device = register(client)
    add_key(client, str(device["id"]), user.address, keys)
    return device, keys


def test_wallet_certificate_activates_the_device(client: TestClient, user: LoggedIn) -> None:
    device, keys = with_certificate(client, user)
    certificate = wallet_certificate(user.account, keys.fingerprint)
    authorized = client.post(f"{DEVICES}/{device['id']}/authorize", json=certificate)
    assert authorized.status_code == 200, authorized.text
    body = authorized.json()
    assert body["status"] == "active" and body["authorized_at"] is not None
    assert body["fingerprint"] == keys.fingerprint
    assert body["certificate_expires_at"] is not None
    # Same certificate again: renewals need a newer one.
    again = client.post(f"{DEVICES}/{device['id']}/authorize", json=certificate)
    assert again.status_code == 409
    assert again.json()["error"]["code"] == "INVALID_STATE"


def test_certificate_renewal_is_audited(client: TestClient, user: LoggedIn) -> None:
    device, keys = with_certificate(client, user)
    first = wallet_certificate(user.account, keys.fingerprint, issued_at=int(time.time()) - 120)
    client.post(f"{DEVICES}/{device['id']}/authorize", json=first)
    renewed = wallet_certificate(user.account, keys.fingerprint)
    response = client.post(f"{DEVICES}/{device['id']}/authorize", json=renewed)
    assert response.status_code == 200 and response.json()["status"] == "active"
    history = client.get(f"{DEVICES}/{device['id']}/events").json()["items"]
    assert history[0]["event_type"] == "device.certificate_renewed"
    assert history[0]["details"]["fingerprint"] == keys.fingerprint


def test_authorization_needs_a_registered_certificate(client: TestClient, user: LoggedIn) -> None:
    device = register(client)
    response = client.post(
        f"{DEVICES}/{device['id']}/authorize", json=wallet_certificate(user.account, "ab" * 32)
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "INVALID_STATE"


def test_foreign_or_mismatched_attestations_are_rejected(
    client: TestClient, user: LoggedIn
) -> None:
    device, keys = with_certificate(client, user)
    other_wallet = Account.create()
    now = int(time.time())
    bad = [
        wallet_certificate(other_wallet, keys.fingerprint),  # not the account's wallet
        wallet_certificate(user.account, "cd" * 32),  # another device's fingerprint
        wallet_certificate(user.account, keys.fingerprint, service="evil.example"),
        wallet_certificate(user.account, keys.fingerprint, chain_id=5),
        wallet_certificate(user.account, keys.fingerprint, issued_at=now + 3600),
        wallet_certificate(user.account, keys.fingerprint, expires_at=now + 500 * 86400),
    ]
    for payload in bad:
        response = client.post(f"{DEVICES}/{device['id']}/authorize", json=payload)
        assert response.status_code == 422, payload
        assert response.json()["error"]["code"] == "ATTESTATION_REJECTED"
    assert client.get(f"{DEVICES}/{device['id']}").json()["status"] == "pending"
    for malformed in ({}, {"issued_at": 1, "expires_at": 2, "signature": "0x12"}):
        response = client.post(f"{DEVICES}/{device['id']}/authorize", json=malformed)
        assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_authorization_does_not_need_step_up_any_more(
    client: TestClient, user: LoggedIn, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The wallet signature is the approval; an old session can submit it."""
    device, keys = with_certificate(client, user)

    class Later:
        @staticmethod
        def time() -> float:
            return time.time() + 601  # default step-up window is 600 s

    monkeypatch.setattr(dependencies, "time", Later)
    response = client.post(
        f"{DEVICES}/{device['id']}/authorize",
        json=wallet_certificate(user.account, keys.fingerprint),
    )
    assert response.status_code == 200


def test_revoke_is_terminal_and_records_reason(client: TestClient, user: LoggedIn) -> None:
    device, keys = with_certificate(client, user)
    certificate = wallet_certificate(user.account, keys.fingerprint)
    client.post(f"{DEVICES}/{device['id']}/authorize", json=certificate)
    revoked = client.post(f"{DEVICES}/{device['id']}/revoke", json={"reason": "lost phone"})
    assert revoked.status_code == 200
    body = revoked.json()
    assert body["status"] == "revoked"
    assert body["revocation_reason"] == "lost phone"
    assert body["revoked_at"] is not None
    for action, payload in (("revoke", {}), ("authorize", certificate)):
        response = client.post(f"{DEVICES}/{device['id']}/{action}", json=payload)
        assert response.status_code == 409, action
        assert response.json()["error"]["code"] == "INVALID_STATE"


def test_wallet_signed_revocation_is_published(client: TestClient, user: LoggedIn) -> None:
    device, keys = with_certificate(client, user)
    client.post(
        f"{DEVICES}/{device['id']}/authorize",
        json=wallet_certificate(user.account, keys.fingerprint),
    )
    forged = wallet_revocation(Account.create(), keys.fingerprint)
    response = client.post(f"{DEVICES}/{device['id']}/revoke", json={"wallet_revocation": forged})
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "ATTESTATION_REJECTED"
    assert client.get(f"{DEVICES}/{device['id']}").json()["status"] == "active"

    signed = wallet_revocation(user.account, keys.fingerprint)
    response = client.post(f"{DEVICES}/{device['id']}/revoke", json={"wallet_revocation": signed})
    assert response.status_code == 200
    directory = client.get(f"/v1/keys/{user.address}").json()
    assert directory["keys"] == []
    assert directory["revocations"] == [
        {
            "device_fingerprint": keys.fingerprint,
            "revoked_at": signed["revoked_at"],
            "signature": signed["signature"],
        }
    ]


def test_pending_device_can_be_rejected(client: TestClient, user: LoggedIn) -> None:
    device = register(client)
    response = client.post(f"{DEVICES}/{device['id']}/revoke", json={})
    assert response.status_code == 200
    assert response.json()["status"] == "revoked"
    assert response.json()["authorized_at"] is None


@pytest.mark.parametrize("payload", [{"reason": ""}, {"reason": "x" * 201}, {"why": "x"}])
def test_revoke_rejects_invalid_payloads(
    client: TestClient, user: LoggedIn, payload: dict[str, object]
) -> None:
    device = register(client)
    assert client.post(f"{DEVICES}/{device['id']}/revoke", json=payload).status_code == 422


def test_history_lists_events_newest_first(client: TestClient, user: LoggedIn) -> None:
    device, keys = with_certificate(client, user)
    client.post(
        f"{DEVICES}/{device['id']}/authorize",
        json=wallet_certificate(user.account, keys.fingerprint),
    )
    client.post(f"{DEVICES}/{device['id']}/revoke", json={"reason": "rotated"})
    history = client.get(f"{DEVICES}/{device['id']}/events").json()
    assert history["total"] == 5
    types = [event["event_type"] for event in history["items"]]
    assert types == [
        "device.revoked",
        "key.revoked",
        "device.authorized",
        "key.registered",
        "device.registered",
    ]
    sequences = [event["sequence"] for event in history["items"]]
    assert sequences == sorted(sequences, reverse=True)
    revoked = history["items"][0]
    assert revoked["details"]["reason"] == "rotated"
    assert revoked["details"]["from"] == "active"
    assert revoked["actor_user_id"] == user.user_id
    client_fp = revoked["details"]["client"]
    assert set(client_fp) == {"ua", "net"} and all(len(v) == 64 for v in client_fp.values())
    assert "AgnusTest" not in str(history)


def test_endpoints_require_authentication(client: TestClient) -> None:
    some_id = "00000000-0000-4000-8000-000000000000"
    calls = [
        ("get", DEVICES, None),
        ("post", DEVICES, {"name": "x"}),
        ("get", f"{DEVICES}/{some_id}", None),
        ("post", f"{DEVICES}/{some_id}/authorize", {}),
        ("post", f"{DEVICES}/{some_id}/revoke", {}),
        ("get", f"{DEVICES}/{some_id}/events", None),
    ]
    for method, url, body in calls:
        response = client.request(method, url, json=body)
        assert response.status_code == 401, (method, url)
        assert response.json()["error"]["code"] == "NO_SESSION"
