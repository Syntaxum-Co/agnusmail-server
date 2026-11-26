"""Public key directory API with protocol v1 device certificates."""

import json
import secrets
import time
from collections.abc import Iterator
from typing import Any

import pytest
from eth_account import Account
from fastapi.testclient import TestClient

from agnusmail.modules.authentication import dependencies
from agnusmail.modules.identity.models import User, UserStatus
from agnusmail.testing.auth import LoggedIn, login
from agnusmail.testing.devices import (
    DEVICES,
    FORMAT,
    add_key,
    key_payload,
    next_version,
    onboard,
    wallet_certificate,
)
from agnusmail.testing.fakes import make_app, make_session_factory, make_settings
from agnusmail.testing.openpgp import DIRECT_KEY, b64, new_device, tamper_signature


@pytest.fixture
def client() -> Iterator[TestClient]:
    app, _ = make_app()
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client


@pytest.fixture
def user(client: TestClient) -> LoggedIn:
    return login(client)


def pending_device_id(client: TestClient) -> str:
    device_id: str = client.post(DEVICES, json={"name": "device"}).json()["id"]
    return device_id


def directory(client: TestClient, address: str) -> list[dict[str, Any]]:
    response = client.get(f"/v1/keys/{address}")
    assert response.status_code == 200, response.text
    return response.json()["keys"]  # type: ignore[no-any-return]


def rejected(client: TestClient, device_id: str, payload: dict[str, Any]) -> str:
    response = client.post(f"{DEVICES}/{device_id}/keys", json=payload)
    assert response.status_code == 422, response.text
    error = response.json()["error"]
    assert error["code"] == "KEY_REJECTED"
    return str(error["detail"])


class Stale:
    """Clock 601 s ahead: the session is outside the step-up window."""

    @staticmethod
    def time() -> float:
        return time.time() + 601


def test_certificate_on_pending_device_is_published_only_after_authorization(
    client: TestClient, user: LoggedIn
) -> None:
    device = new_device()
    device_id = pending_device_id(client)
    key = add_key(client, device_id, user.address, device)
    assert key["version"] == 1 and key["status"] == "active"
    assert key["format"] == FORMAT
    assert key["material"] == b64(device.material)
    assert key["fingerprint"] == device.fingerprint
    assert len(key["encryption_fingerprint"]) == 64 and key["expires_at"]
    assert key["material_digest"].startswith("sha256:") and len(key["material_digest"]) == 71
    assert directory(client, user.address) == []

    certificate = wallet_certificate(user.account, device.fingerprint)
    client.post(f"{DEVICES}/{device_id}/authorize", json=certificate)
    published = directory(client, user.address)
    assert [k["key_id"] for k in published] == [key["id"]]
    assert set(published[0]) == {
        "key_id",
        "device_id",
        "version",
        "format",
        "material",
        "material_digest",
        "fingerprint",
        "encryption_fingerprint",
        "expires_at",
        "created_at",
        "device_certificate",
    }
    assert published[0]["device_certificate"] == certificate


def test_new_versions_keep_the_primary_key_and_supersede(
    client: TestClient, user: LoggedIn
) -> None:
    onboarded = onboard(client, user)
    device, device_id, first = onboarded.keys, onboarded.device_id, onboarded.key
    second = add_key(client, device_id, user.address, device, material=next_version(device))
    assert (first["version"], second["version"]) == (1, 2)
    assert first["fingerprint"] == second["fingerprint"] == device.fingerprint

    versions = client.get(f"{DEVICES}/{device_id}/keys").json()
    assert [k["version"] for k in versions["items"]] == [2, 1]
    assert versions["items"][1]["status"] == "superseded" and versions["items"][1]["superseded_at"]
    assert [k["key_id"] for k in directory(client, user.address)] == [second["id"]]

    message = rejected(client, device_id, key_payload(user.address))  # other primary key
    assert "primary key" in message


def test_publishing_to_active_device_requires_recent_login(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    account = Account.create()
    me = login(client, account)
    onboarded = onboard(client, me)
    device, active = onboarded.keys, onboarded.device_id
    pending = pending_device_id(client)
    monkeypatch.setattr(dependencies, "time", Stale)

    refreshed = next_version(device)
    stale = client.post(
        f"{DEVICES}/{active}/keys", json=key_payload(me.address, device, material=refreshed)
    )
    assert stale.status_code == 403
    assert stale.json()["error"]["code"] == "REAUTHENTICATION_REQUIRED"
    # Pending devices are not published yet, so no step-up is needed to upload.
    add_key(client, pending, me.address)

    monkeypatch.undo()
    login(client, account)
    add_key(client, active, me.address, device, material=refreshed)


def test_revoking_a_key_unpublishes_it(client: TestClient, user: LoggedIn) -> None:
    onboarded = onboard(client, user)
    device_id, key = onboarded.device_id, onboarded.key
    revoked = client.post(f"{DEVICES}/{device_id}/keys/{key['id']}/revoke")
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked" and revoked.json()["revoked_at"]
    assert directory(client, user.address) == []
    again = client.post(f"{DEVICES}/{device_id}/keys/{key['id']}/revoke")
    assert again.status_code == 409
    assert again.json()["error"]["code"] == "INVALID_STATE"


def test_key_ids_are_scoped_to_their_device(client: TestClient, user: LoggedIn) -> None:
    first = onboard(client, user)
    device_a, key = first.device_id, first.key
    device_b = onboard(client, user).device_id
    wrong_device = client.post(f"{DEVICES}/{device_b}/keys/{key['id']}/revoke")
    assert wrong_device.status_code == 404
    unknown = client.post(f"{DEVICES}/{device_a}/keys/{secrets.token_hex(16)}/revoke")
    assert unknown.status_code == 404  # 32 hex digits are a valid (unhyphenated) UUID
    malformed = client.post(f"{DEVICES}/{device_a}/keys/not-a-uuid/revoke")
    assert malformed.status_code == 422


def test_revoking_device_revokes_all_its_keys(client: TestClient, user: LoggedIn) -> None:
    onboarded = onboard(client, user)
    device, device_id = onboarded.keys, onboarded.device_id
    add_key(client, device_id, user.address, device, material=next_version(device))
    client.post(f"{DEVICES}/{device_id}/revoke", json={"reason": "stolen"})

    keys = client.get(f"{DEVICES}/{device_id}/keys").json()["items"]
    assert {k["status"] for k in keys} == {"revoked"}
    assert all(k["revoked_at"] for k in keys)
    assert directory(client, user.address) == []
    history = client.get(f"{DEVICES}/{device_id}/events", params={"limit": 100}).json()["items"]
    cascade = [e for e in history if e["details"].get("cause") == "device_revoked"]
    assert len(cascade) == 2
    assert history[0]["event_type"] == "device.revoked"
    assert history[0]["details"]["keys_revoked"] == 2

    blocked = client.post(f"{DEVICES}/{device_id}/keys", json=key_payload(user.address, device))
    assert blocked.status_code == 409
    assert blocked.json()["error"]["code"] == "INVALID_STATE"


def test_a_certificate_stands_for_one_device_only(client: TestClient, user: LoggedIn) -> None:
    device = onboard(client, user).keys
    second = pending_device_id(client)
    duplicate = client.post(f"{DEVICES}/{second}/keys", json=key_payload(user.address, device))
    assert duplicate.status_code == 409
    assert duplicate.json()["error"]["code"] == "DEVICE_KEY_IN_USE"

    # Another account cannot claim it either, even with a fresh proof for itself.
    other = login(client)
    other_device = pending_device_id(client)
    stolen = client.post(f"{DEVICES}/{other_device}/keys", json=key_payload(other.address, device))
    assert stolen.status_code == 409
    assert stolen.json()["error"]["code"] == "DEVICE_KEY_IN_USE"
    assert client.get(f"{DEVICES}/{other_device}/keys").json()["total"] == 0


def test_proof_of_possession_is_bound_to_account_and_service(
    client: TestClient, user: LoggedIn
) -> None:
    device_id = pending_device_id(client)
    device = new_device()
    other_account = "0x" + secrets.token_hex(20)
    assert "proof" in rejected(client, device_id, key_payload(other_account, device))
    assert "proof" in rejected(client, device_id, key_payload(user.address, device, service="x"))
    replayed = key_payload(user.address, device) | {"proof": key_payload(user.address)["proof"]}
    assert "proof" in rejected(client, device_id, replayed)  # proof of another certificate
    assert client.get(f"{DEVICES}/{device_id}/keys").json()["total"] == 0


@pytest.mark.parametrize(
    ("make_material", "reason"),
    [
        (lambda: bytes(new_device().tsk), "private key"),
        (lambda: str(new_device().cert).encode(), "private key"),  # armored: textual guard
        (lambda: new_device(validity_days=None).material, "no_expiration"),
        (lambda: tamper_signature(new_device().material, DIRECT_KEY), "self_signature_invalid"),
        (lambda: b"\x00not openpgp", "malformed"),
    ],
)
def test_invalid_certificates_are_rejected(
    client: TestClient, user: LoggedIn, make_material: Any, reason: str
) -> None:
    device_id = pending_device_id(client)
    payload = key_payload(user.address) | {"material": b64(make_material())}
    message = rejected(client, device_id, payload)
    assert reason in message or (reason == "private key" and "armored" in message)
    assert client.get(f"{DEVICES}/{device_id}/keys").json()["total"] == 0


def test_only_the_protocol_format_is_accepted(client: TestClient, user: LoggedIn) -> None:
    device_id = pending_device_id(client)
    payload = key_payload(user.address) | {"format": "opaque-test-v0"}
    assert "unsupported key format" in rejected(client, device_id, payload)


def test_key_version_limit() -> None:
    app, _ = make_app(make_settings(max_keys_per_device=2))
    with TestClient(app, raise_server_exceptions=False) as client:
        me = login(client)
        onboarded = onboard(client, me)
        device, device_id = onboarded.keys, onboarded.device_id
        add_key(client, device_id, me.address, device, material=next_version(device, 1))
        third = key_payload(me.address, device, material=next_version(device, 2))
        blocked = client.post(f"{DEVICES}/{device_id}/keys", json=third)
        assert blocked.status_code == 409
        assert blocked.json()["error"]["code"] == "LIMIT_EXCEEDED"


def test_oversized_material_is_rejected() -> None:
    app, _ = make_app(make_settings(max_public_key_bytes=1024))
    with TestClient(app, raise_server_exceptions=False) as client:
        me = login(client)
        device_id = pending_device_id(client)
        assert "exceeds" in rejected(client, device_id, key_payload(me.address))


@pytest.mark.parametrize(
    "payload",
    [
        {"format": FORMAT, "material": "YQ", "proof": "YWJj"},  # missing padding
        {"format": FORMAT, "material": "YR==", "proof": "YWJj"},  # non-zero padding bits
        {"format": FORMAT, "material": "YW Jj", "proof": "YWJj"},  # whitespace
        {"format": FORMAT, "material": "-_-_", "proof": "YWJj"},  # url-safe alphabet
        {"format": FORMAT, "material": "", "proof": "YWJj"},
        {"format": FORMAT, "material": 123, "proof": "YWJj"},
        {"format": FORMAT, "material": "YWJj"},  # no proof
        {"format": "Upper", "material": "YWJj", "proof": "YWJj"},
        {"format": FORMAT, "material": "YWJj", "proof": "YWJj", "private": "x"},  # unknown
        {"material": "YWJj", "proof": "YWJj"},
    ],
)
def test_invalid_key_payloads_are_422(
    client: TestClient, user: LoggedIn, payload: dict[str, Any]
) -> None:
    device_id = pending_device_id(client)
    response = client.post(f"{DEVICES}/{device_id}/keys", json=payload)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_directory_lookup_rules() -> None:
    factory = make_session_factory()
    app, _ = make_app(session_factory=factory)
    with TestClient(app, raise_server_exceptions=False) as client:
        assert client.get(f"/v1/keys/0x{'ab' * 20}").status_code == 401  # needs a session
        owner = login(client)
        key = onboard(client, owner).key

        upper = "0x" + owner.address[2:].upper()
        lookup = client.get(f"/v1/keys/{upper}").json()
        assert lookup["address"] == owner.address.lower()
        assert (lookup["service"], lookup["chain_id"]) == ("app.agnusmail", 1)
        assert lookup["revocations"] == []
        assert [k["key_id"] for k in lookup["keys"]] == [key["id"]]

        unknown = client.get(f"/v1/keys/0x{secrets.token_hex(20)}")
        assert unknown.status_code == 200 and unknown.json()["keys"] == []
        for bad in ("0x123", "abc", f"0x{'zz' * 20}"):
            assert client.get(f"/v1/keys/{bad}").status_code == 422

        with factory() as session, session.begin():
            row = session.query(User).filter_by(ethereum_address=owner.address.lower()).one()
            row.status = UserStatus.SUSPENDED
        with TestClient(app, raise_server_exceptions=False) as other:
            login(other)  # the suspended owner's own session has ended
            assert directory(other, owner.address) == []  # suspended: not published


def test_audit_never_contains_key_material(client: TestClient, user: LoggedIn) -> None:
    onboarded = onboard(client, user)
    device, device_id, key = onboarded.keys, onboarded.device_id, onboarded.key
    client.post(f"{DEVICES}/{device_id}/keys/{key['id']}/revoke")
    events = client.get(f"{DEVICES}/{device_id}/events").json()["items"]
    types = [e["event_type"] for e in events]
    assert types[:3] == ["key.revoked", "device.authorized", "key.registered"]
    registered = events[2]
    assert registered["public_key_id"] == key["id"]
    assert registered["details"]["material_digest"] == key["material_digest"]
    assert registered["details"]["fingerprint"] == device.fingerprint
    dumped = json.dumps(events)
    assert b64(device.material) not in dumped and device.material.hex() not in dumped
