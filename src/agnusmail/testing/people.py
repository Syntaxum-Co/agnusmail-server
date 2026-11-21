"""Logged-in users with an authorized device and a session bound to it, and the E2EE
messages a client would send (protocol v1 §6). Keys and encryption happen in the test,
on the client's side; the server only sees ciphertext.
"""

import base64
import secrets
from dataclasses import dataclass
from typing import Any

import pysequoia
from fastapi.testclient import TestClient

from agnusmail.infrastructure.openpgp import pkesk_recipient
from agnusmail.testing.auth import LoggedIn, login
from agnusmail.testing.devices import Onboarded, onboard
from agnusmail.testing.openpgp import DeviceKeys, decrypt_joined, encrypt_split

MESSAGES = "/v1/messages"
PLAINTEXT = b"From: alice@example\r\nSubject: secret plans\r\n\r\nMeet at noon.\r\n"


@dataclass
class Person:
    client: TestClient
    user: LoggedIn
    device: Onboarded

    @property
    def keys(self) -> DeviceKeys:
        return self.device.keys


def bind_session(client: TestClient, device: Onboarded) -> None:
    issued = client.post("/v1/auth/device/challenge", json={"device_id": device.device_id}).json()
    signature = base64.b64encode(device.keys.sign(issued["statement"].encode())).decode()
    response = client.post(
        "/v1/auth/device/bind", json={"device_id": device.device_id, "signature": signature}
    )
    assert response.status_code == 200, response.text


def person(app: Any) -> Person:
    client = TestClient(app, raise_server_exceptions=False)
    user = login(client)
    device = onboard(client, user)
    bind_session(client, device)
    return Person(client, user, device)


def second_device(owner: Person, app: Any) -> Person:
    """The same account on a new device (new client, own bound session)."""
    client = TestClient(app, raise_server_exceptions=False)
    login(client, owner.user.account)
    device = onboard(client, owner.user)
    bind_session(client, device)
    return Person(client, owner.user, device)


def published(client: TestClient, address: str) -> list[dict[str, Any]]:
    """Every key a sender must encrypt to: device keys plus the recovery key (§6.2)."""
    directory = client.get(f"/v1/keys/{address}").json()
    keys: list[dict[str, Any]] = list(directory["keys"])
    if directory.get("recovery_key"):
        keys.append(directory["recovery_key"])
    return keys


def compose(
    sender: Person, recipients: list[Person], *, plaintext: bytes = PLAINTEXT
) -> dict[str, Any]:
    """What a client does: fetch the directory, encrypt to every published key (own
    devices included) and route each PKESK by its recipient fingerprint."""
    accounts = {p.user.address: published(sender.client, p.user.address) for p in recipients}
    own = published(sender.client, sender.user.address)
    entries = [k for keys in accounts.values() for k in keys] + own
    certs = [pysequoia.Cert.from_bytes(base64.b64decode(k["material"])) for k in entries]
    pkesks, body = encrypt_split(plaintext, certs, sender.keys)
    by_fpr = {pkesk_recipient(p): base64.b64encode(p).decode() for p in pkesks}
    return {
        "version": 1,
        "message_id": secrets.token_hex(16),
        "recipients": [
            {"account": account, "pkesks": [by_fpr[k["encryption_fingerprint"]] for k in keys]}
            for account, keys in accounts.items()
        ],
        "self_pkesks": [by_fpr[k["encryption_fingerprint"]] for k in own],
        "body": base64.b64encode(body).decode(),
    }


def open_message(reader: Person, message_id: str, sender: Person) -> bytes:
    data = reader.client.get(f"{MESSAGES}/{message_id}").json()
    assert data["pkesks"], data
    plaintext, signatures = decrypt_joined(
        reader.keys,
        base64.b64decode(data["pkesks"][0]),
        base64.b64decode(data["body"]),
        sender.keys.cert,
    )
    assert signatures == 1  # signed by the sender's device
    return plaintext


def send(sender: Person, payload: dict[str, Any]) -> Any:
    return sender.client.post(MESSAGES, json=payload)
