"""Account recovery (protocol v1 §8): recovery key, encrypted backup, migration."""

import base64
import time
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pysequoia
import pytest
from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_account.signers.local import LocalAccount
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.modules.audit.models import AuditEvent
from agnusmail.modules.authentication.stores import (
    SESSION_DATA_PREFIX,
    SESSION_OWNER_PREFIX,
    revoke_owner_sessions_sync,
)
from agnusmail.modules.devices.attestation import (
    MigrationAcceptanceClaim,
    RecoveryKeyClaim,
    migration_acceptance_typed_data,
    recovery_key_typed_data,
)
from agnusmail.modules.devices.schemas import MAX_UNIX_SECONDS
from agnusmail.modules.identity.models import User
from agnusmail.modules.recovery.migration import complete_due_migrations, migration_statement
from agnusmail.modules.recovery.service import RECOVERY_FORMAT, registration_statement
from agnusmail.testing.auth import login
from agnusmail.testing.fakes import make_app, make_session_factory
from agnusmail.testing.openpgp import DeviceKeys, b64, new_device
from agnusmail.testing.people import Person, compose, person
from tests.client_decrypt import decrypt_joined

SERVICE = "app.agnusmail"
VECTORS = Path(__file__).resolve().parent.parent / "vectors"


def wallet_sign(wallet: LocalAccount, typed: dict[str, Any]) -> str:
    signed = Account.sign_message(encode_typed_data(full_message=typed), private_key=wallet.key)
    return "0x" + bytes(signed.signature).hex()


def recovery_payload(owner: Person, keys: DeviceKeys, **override: Any) -> dict[str, Any]:
    issued = int(time.time())
    claim = RecoveryKeyClaim(owner.user.address, keys.fingerprint, SERVICE, issued)
    statement = registration_statement(SERVICE, owner.user.address, keys.fingerprint)
    payload = {
        "format": RECOVERY_FORMAT,
        "material": b64(keys.material),
        "proof": b64(keys.sign(statement)),
        "wallet_certificate": {
            "issued_at": issued,
            "signature": wallet_sign(owner.user.account, recovery_key_typed_data(claim, 1)),
        },
    }
    return payload | override


def register_recovery(owner: Person) -> DeviceKeys:
    keys = new_device()
    response = owner.client.post("/v1/recovery/key", json=recovery_payload(owner, keys))
    assert response.status_code == 201, response.text
    return keys


@pytest.fixture
def factory() -> sessionmaker[Session]:
    return make_session_factory()


@pytest.fixture
def app(factory: sessionmaker[Session]) -> Any:
    return make_app(session_factory=factory)[0]


@pytest.fixture
def alice(app: Any) -> Iterator[Person]:
    p = person(app)
    yield p
    p.client.close()


@pytest.fixture
def bob(app: Any) -> Iterator[Person]:
    p = person(app)
    yield p
    p.client.close()


# --- recovery key ------------------------------------------------------------------------


def test_recovery_key_is_published_and_audited(
    alice: Person, bob: Person, factory: sessionmaker[Session]
) -> None:
    keys = register_recovery(alice)
    mine = alice.client.get("/v1/recovery/key").json()
    assert mine["fingerprint"] == keys.fingerprint
    assert mine["wallet_account"] == alice.user.address.lower()
    directory = bob.client.get(f"/v1/keys/{alice.user.address}").json()
    assert directory["recovery_key"]["encryption_fingerprint"] == mine["encryption_fingerprint"]
    with factory() as session:
        kinds = session.scalars(select(AuditEvent.event_type)).all()
    assert "recovery.key_registered" in kinds


def test_recovery_key_needs_its_proofs(alice: Person) -> None:
    keys = new_device()
    stranger = Account.create()
    claim = RecoveryKeyClaim(alice.user.address, keys.fingerprint, SERVICE, int(time.time()))
    cases: list[tuple[dict[str, Any], int]] = [
        ({"proof": b64(keys.sign(b"wrong statement"))}, 422),
        (
            {
                "wallet_certificate": {
                    "issued_at": claim.issued_at,
                    "signature": wallet_sign(stranger, recovery_key_typed_data(claim, 1)),
                }
            },
            422,
        ),
        ({"format": "openpgp-v6/agnusmail-device-1"}, 422),
    ]
    for override, status in cases:
        response = alice.client.post(
            "/v1/recovery/key", json=recovery_payload(alice, keys, **override)
        )
        assert response.status_code == status, override
    # A device certificate cannot double as the recovery key.
    device_cert = recovery_payload(alice, alice.keys)
    assert alice.client.post("/v1/recovery/key", json=device_cert).status_code == 409


def test_replacing_the_recovery_key_keeps_one_active(alice: Person) -> None:
    register_recovery(alice)
    second = register_recovery(alice)
    assert alice.client.get("/v1/recovery/key").json()["fingerprint"] == second.fingerprint


# --- messages carry a PKESK for the recovery key -----------------------------------------


def test_messages_include_the_recovery_key_and_it_restores_access(
    app: Any, alice: Person, bob: Person
) -> None:
    recovery = register_recovery(bob)
    outdated = compose(alice, [bob])
    assert len(outdated["recipients"][0]["pkesks"]) == 2  # bob's device + recovery key
    outdated["recipients"][0]["pkesks"] = outdated["recipients"][0]["pkesks"][:1]
    missing = alice.client.post("/v1/messages", json=outdated)
    assert missing.status_code == 409  # a client ignoring the recovery key is refused

    sent = alice.client.post("/v1/messages", json=compose(alice, [bob]))
    assert sent.status_code == 201, sent.text
    message = bob.client.get(f"/v1/messages/{sent.json()['id']}").json()
    assert len(message["recovery_pkesks"]) == 1

    # Restore (§8.4): with the recovery key, a NEW device recovers the session key and
    # gets the message shared with it, without the old device.
    plaintext, signatures = decrypt_joined(
        recovery,
        base64.b64decode(message["recovery_pkesks"][0]),
        base64.b64decode(message["body"]),
        alice.keys.cert,
    )
    assert plaintext.startswith(b"From: alice") and signatures == 1


# --- encrypted backup --------------------------------------------------------------------


def test_backup_versions_and_structure(alice: Person) -> None:
    good = (VECTORS / "recovery_backup_openpgpjs.pgp").read_bytes()  # OpenPGP.js v7, Argon2
    assert alice.client.put("/v1/recovery/backup", json={"blob": b64(good)}).status_code == 409
    register_recovery(alice)
    first = alice.client.put("/v1/recovery/backup", json={"blob": b64(good)})
    second = alice.client.put("/v1/recovery/backup", json={"blob": b64(good)})
    assert (first.json()["version"], second.json()["version"]) == (1, 2)
    latest = alice.client.get("/v1/recovery/backup").json()
    assert latest["version"] == 2 and base64.b64decode(latest["blob"]) == good

    weak = (VECTORS / "recovery_backup_weak_argon2.pgp").read_bytes()
    legacy = pysequoia.encrypt(b"secret", passwords=["words"], armor=False)  # SKESK v4
    for blob in (weak, legacy, b"\x00garbage"):
        response = alice.client.put("/v1/recovery/backup", json={"blob": b64(blob)})
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "BACKUP_REJECTED"
    assert alice.client.get("/v1/recovery/backup").json()["version"] == 2  # nothing stored


# --- wallet migration --------------------------------------------------------------------


def migration_payload(
    owner: Person, recovery: DeviceKeys, new_wallet: LocalAccount, **o: Any
) -> dict[str, Any]:
    issued = int(time.time())
    old, new = owner.user.address, new_wallet.address
    statement = migration_statement(SERVICE, old, new, issued)
    claim = MigrationAcceptanceClaim(old, new, recovery.fingerprint, SERVICE, issued)
    payload = {
        "old_account": old,
        "new_account": new,
        "issued_at": issued,
        "recovery_signature": b64(recovery.sign(statement)),
        "acceptance_signature": wallet_sign(new_wallet, migration_acceptance_typed_data(claim, 1)),
    }
    return payload | o


def test_migration_waits_seven_days_and_can_be_cancelled(app: Any, alice: Person) -> None:
    recovery = register_recovery(alice)
    with TestClient(app, raise_server_exceptions=False) as anonymous:
        response = anonymous.post(
            "/v1/recovery/migrations", json=migration_payload(alice, recovery, Account.create())
        )
    assert response.status_code == 202, response.text
    migration = response.json()
    requested = datetime.fromisoformat(migration["requested_at"])
    assert datetime.fromisoformat(migration["effective_at"]) - requested == timedelta(days=7)
    pending = alice.client.get("/v1/recovery/migrations").json()["items"]
    assert [m["status"] for m in pending] == ["pending"]  # devices can warn the owner
    events = alice.client.get("/v1/audit/events", params={"limit": 200}).json()["items"]
    assert events[-1]["event_type"] == "recovery.migration_requested"
    assert events[-1]["actor_user_id"] is None

    cancel = alice.client.post(f"/v1/recovery/migrations/{migration['id']}/cancel")
    assert cancel.status_code == 200 and cancel.json()["status"] == "cancelled"
    assert alice.client.post(f"/v1/recovery/migrations/{migration['id']}/cancel").status_code == 409


def test_migration_requests_need_valid_proofs(app: Any, alice: Person) -> None:
    recovery = register_recovery(alice)
    new_wallet, other = Account.create(), Account.create()
    good = migration_payload(alice, recovery, new_wallet)
    forged_acceptance = migration_payload(alice, recovery, other) | {
        "new_account": new_wallet.address
    }
    cases = [
        good | {"recovery_signature": b64(new_device().sign(b"x"))},
        forged_acceptance,
        good | {"issued_at": good["issued_at"] - 3600},
        good | {"old_account": "0x" + "12" * 20},
    ]
    with TestClient(app, raise_server_exceptions=False) as anonymous:
        for payload in cases:
            response = anonymous.post("/v1/recovery/migrations", json=payload)
            assert response.status_code == 422, payload
            assert response.json()["error"]["code"] == "MIGRATION_REJECTED"
        login(anonymous, new_wallet)  # the new wallet already has an account now
        assert anonymous.post("/v1/recovery/migrations", json=good).status_code == 409


def test_timestamps_past_year_9999_are_refused_not_crashed(app: Any, alice: Person) -> None:
    """``issued_at`` past 9999-12-31 used to escape ``datetime.fromtimestamp`` as a 500 on
    this session-less route."""
    good = migration_payload(alice, register_recovery(alice), Account.create())
    with TestClient(app, raise_server_exceptions=False) as anonymous:
        for issued_at in (MAX_UNIX_SECONDS + 1, 2**63 - 1):
            payload = good | {"issued_at": issued_at}
            response = anonymous.post("/v1/recovery/migrations", json=payload)
            assert response.status_code == 422, issued_at
            assert response.json()["error"]["code"] == "VALIDATION_ERROR"
    # The bound is the last second datetime can hold (fromtimestamp is platform-bound).
    last = datetime(1970, 1, 1, tzinfo=UTC) + timedelta(seconds=MAX_UNIX_SECONDS)
    assert last == datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC)


def test_completed_migration_moves_the_account(
    app: Any, alice: Person, bob: Person, factory: sessionmaker[Session]
) -> None:
    recovery = register_recovery(alice)
    new_wallet = Account.create()
    with TestClient(app, raise_server_exceptions=False) as anonymous:
        response = anonymous.post(
            "/v1/recovery/migrations", json=migration_payload(alice, recovery, new_wallet)
        )
    assert response.status_code == 202
    with factory() as session, session.begin():
        assert complete_due_migrations(session, datetime.now(UTC)) == []  # still waiting
        done = complete_due_migrations(session, datetime.now(UTC) + timedelta(days=8))
    assert len(done) == 1

    with factory() as session:
        user = session.get(User, uuid.UUID(alice.user.user_id))
        assert user is not None and user.ethereum_address == new_wallet.address.lower()
    with TestClient(app, raise_server_exceptions=False) as fresh:
        assert login(fresh, new_wallet).user_id == alice.user.user_id  # same account
    evidence = bob.client.get(f"/v1/keys/{new_wallet.address}").json()["migrations"]
    assert [(m["old_account"], m["new_account"]) for m in evidence] == [
        (alice.user.address.lower(), new_wallet.address.lower())
    ]
    assert bob.client.get(f"/v1/keys/{alice.user.address}").json()["keys"] == []


class SyncRedis:
    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data

    def zrange(self, key: str, _start: int, _end: int) -> list[str]:
        return list(self.data.get(key, []))

    def delete(self, key: str) -> int:
        return 1 if self.data.pop(key, None) is not None else 0


def test_sync_session_revocation_for_the_worker() -> None:
    data: dict[str, Any] = {
        SESSION_OWNER_PREFIX + "u1": ["d1", "d2"],
        SESSION_DATA_PREFIX + "d1": "{}",
    }
    assert revoke_owner_sessions_sync(SyncRedis(data), "u1") == 1
    assert data == {}
