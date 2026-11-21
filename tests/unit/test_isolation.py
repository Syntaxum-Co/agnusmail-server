"""Cross-account isolation and audit completeness (entrega D).

SECURITY.md requires negative authorization tests: user B must not read or change any
device, key or history of user A, and must not even learn whether they exist (404).
"""

import time
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.openpgp_helpers import DeviceKeys
from tests.unit.auth_helpers import LoggedIn, login
from tests.unit.device_helpers import key_payload, next_version, onboard, wallet_certificate
from tests.unit.fakes import make_app

DEVICES = "/v1/devices"


@dataclass
class World:
    alice: TestClient
    bob: TestClient
    alice_user: LoggedIn
    bob_user: LoggedIn
    pending_device: str
    active_device: str
    key_id: str
    alice_cert: DeviceKeys


@pytest.fixture
def world() -> Iterator[World]:
    app, _ = make_app()
    with (
        TestClient(app, raise_server_exceptions=False) as alice,
        TestClient(app, raise_server_exceptions=False) as bob,
    ):
        alice_user = login(alice)
        bob_user = login(bob)
        pending = alice.post(DEVICES, json={"name": "alice pending"}).json()["id"]
        active = onboard(alice, alice_user, name="alice active")
        yield World(
            alice,
            bob,
            alice_user,
            bob_user,
            pending,
            active.device_id,
            active.key["id"],
            active.keys,
        )


def attempts(w: World) -> list[tuple[str, str, Any]]:
    d, p, k = w.active_device, w.pending_device, w.key_id
    return [
        ("get", f"{DEVICES}/{d}", None),
        ("get", f"{DEVICES}/{d}/events", None),
        ("get", f"{DEVICES}/{d}/keys", None),
        # Valid wallet attestation from Bob: only ownership can stop it (404).
        ("post", f"{DEVICES}/{p}/authorize", wallet_certificate(w.bob_user.account, "ab" * 32)),
        ("post", f"{DEVICES}/{d}/revoke", {}),
        ("post", f"{DEVICES}/{p}/revoke", {"reason": "hijack"}),
        # Valid certificates and proofs for Bob: only ownership can stop them (404).
        ("post", f"{DEVICES}/{d}/keys", key_payload(w.bob_user.address)),
        ("post", f"{DEVICES}/{p}/keys", key_payload(w.bob_user.address)),
        ("post", f"{DEVICES}/{d}/keys/{k}/revoke", None),
    ]


def test_other_users_resources_are_invisible_and_immutable(world: World) -> None:
    before_devices = world.alice.get(DEVICES).json()
    before_keys = world.alice.get(f"{DEVICES}/{world.active_device}/keys").json()
    before_events = world.alice.get(f"{DEVICES}/{world.active_device}/events").json()

    for method, url, body in attempts(world):
        response = world.bob.request(method, url, json=body)
        assert response.status_code == 404, (method, url, response.text)
        assert response.json()["error"]["code"] == "NOT_FOUND", (method, url)

    assert world.alice.get(DEVICES).json() == before_devices
    assert world.alice.get(f"{DEVICES}/{world.active_device}/keys").json() == before_keys
    assert world.alice.get(f"{DEVICES}/{world.active_device}/events").json() == before_events


def test_foreign_and_nonexistent_ids_are_indistinguishable(world: World) -> None:
    missing = "00000000-0000-4000-8000-000000000000"
    foreign = world.bob.get(f"{DEVICES}/{world.active_device}")
    absent = world.bob.get(f"{DEVICES}/{missing}")
    assert foreign.status_code == absent.status_code == 404
    assert foreign.json() == absent.json()


def test_listings_only_contain_own_devices(world: World) -> None:
    bob_devices = world.bob.get(DEVICES).json()
    assert bob_devices["total"] == 0 and bob_devices["items"] == []
    world.bob.post(DEVICES, json={"name": "bob device"})
    names = [d["name"] for d in world.bob.get(DEVICES).json()["items"]]
    assert names == ["bob device"]


def test_directory_is_the_only_cross_account_view(world: World) -> None:
    published = world.bob.get(f"/v1/keys/{world.alice_user.address}").json()["keys"]
    assert [k["key_id"] for k in published] == [world.key_id]
    exposed = set(published[0])
    assert "name" not in exposed and "status" not in exposed  # no device names/history


def test_every_change_is_audited_with_actor_and_failures_leave_no_trace(world: World) -> None:
    alice, device = world.alice, world.active_device
    first = alice.get(f"{DEVICES}/{device}/events").json()
    assert [e["event_type"] for e in first["items"]] == [
        "device.authorized",
        "key.registered",
        "device.registered",
    ]
    assert {e["actor_user_id"] for e in first["items"]} == {world.alice_user.user_id}

    # Rejected operations must not write audit events.
    # Older than the active certificate (issued "now - 60" at setup): never newer, even if
    # a second boundary passes in between (that made this test flaky).
    same = wallet_certificate(
        world.alice_user.account, world.alice_cert.fingerprint, issued_at=int(time.time()) - 3600
    )
    alice.post(f"{DEVICES}/{device}/authorize", json=same)  # 409/422: not a newer certificate
    alice.post(f"{DEVICES}/{device}/keys", json={"format": "BAD", "material": "x"})  # 422
    assert alice.get(f"{DEVICES}/{device}/events").json()["total"] == first["total"]

    refreshed = next_version(world.alice_cert)
    payload = key_payload(world.alice_user.address, world.alice_cert, material=refreshed)
    second_key = alice.post(f"{DEVICES}/{device}/keys", json=payload).json()
    alice.post(f"{DEVICES}/{device}/keys/{second_key['id']}/revoke")
    alice.post(f"{DEVICES}/{device}/revoke", json={})
    alice.post(f"{DEVICES}/{world.pending_device}/revoke", json={})
    events = alice.get(f"{DEVICES}/{device}/events").json()["items"]
    summary = [(e["event_type"], e["details"].get("cause")) for e in events]
    assert summary[:5] == [
        ("device.revoked", None),
        ("key.revoked", "device_revoked"),  # cascade also marks the superseded first key
        ("key.revoked", "user_request"),  # explicit revocation of the second key
        ("key.registered", None),
        ("key.superseded", None),
    ]
    pending_types = [
        e["event_type"]
        for e in alice.get(f"{DEVICES}/{world.pending_device}/events").json()["items"]
    ]
    assert pending_types == ["device.revoked", "device.registered"]
