"""Inbound SMTP gateway (protocol v1 §9): encryption on arrival, in memory."""

import base64
import logging
import smtplib
import socket
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pysequoia
import pytest
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP
from fastapi.testclient import TestClient
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.core.config import Settings
from agnusmail.infrastructure.openpgp import (
    EnvelopeRejectedError,
    GatewayKey,
    generate_gateway_key,
    load_gateway_key,
    split_packets,
)
from agnusmail.modules.devices.models import Device
from agnusmail.modules.inbound import delivery
from agnusmail.modules.inbound.delivery import Arrival, GatewayContext, register_gateway_key
from agnusmail.modules.inbound.smtp import InboundHandler, build_smtp
from agnusmail.modules.messages.models import Message
from tests.openpgp_helpers import DeviceKeys
from tests.unit.auth_helpers import login
from tests.unit.fakes import make_app, make_session_factory, make_settings
from tests.unit.test_messages import Person, person, second_device
from tests.unit.test_recovery import register_recovery

DOMAIN = "mail.agnusmail.test"
EXTERNAL = (
    b"From: Someone <someone@example.org>\r\nSubject: hello\r\n\r\nTEST-ONLY external body\r\n"
)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class Gateway(Controller):
    def __init__(self, handler: InboundHandler, settings: Settings) -> None:
        super().__init__(handler, hostname="127.0.0.1", port=free_port())
        self.settings = settings

    def factory(self) -> SMTP:
        return build_smtp(self.handler, self.settings)


@pytest.fixture
def settings() -> Settings:
    return make_settings(mail_domain=DOMAIN, max_message_recipients=3)


@pytest.fixture
def factory() -> sessionmaker[Session]:
    return make_session_factory()


@pytest.fixture
def app(settings: Settings, factory: sessionmaker[Session]) -> Any:
    return make_app(settings, factory)[0]


@pytest.fixture(scope="module")
def signing_key() -> GatewayKey:
    return load_gateway_key(generate_gateway_key(), now=datetime.now(UTC))


@pytest.fixture
def gateway(
    settings: Settings, factory: sessionmaker[Session], signing_key: GatewayKey
) -> Iterator[Gateway]:
    with factory() as session, session.begin():  # as the process does before listening
        register_gateway_key(session, signing_key)
    ctx = GatewayContext.from_settings(settings, signing_key)
    handler = InboundHandler(factory, ctx, settings)
    controller = Gateway(handler, settings)
    controller.start()
    yield controller
    controller.stop()


def with_address(owner: Person, name: str) -> str:
    response = owner.client.post("/v1/addresses", json={"local_part": name})
    assert response.status_code == 201, response.text
    return f"{name}@{DOMAIN}"


def smtp(gateway: Gateway) -> smtplib.SMTP:
    client = smtplib.SMTP(gateway.hostname, gateway.port, timeout=10)
    client.ehlo("mx.example.org")
    return client


def published_gateway_certs(client: TestClient) -> list[Any]:
    """Client role: the gateway certificates from the public route."""
    items = client.get("/v1/gateway/keys").json()["items"]
    return [pysequoia.Cert.from_bytes(base64.b64decode(item["material"])) for item in items]


def decrypt_external(client: TestClient, keys: DeviceKeys, pkesk: bytes, body: bytes) -> bytes:
    """Client role: ``PKESK || body``, signed by a published gateway key (spec §9)."""
    certs = published_gateway_certs(client)
    result = pysequoia.decrypt(
        decryptor=keys.tsk.decryptor(), bytes=pkesk + body, store=lambda _ids: certs
    )
    # The store holds only gateway certificates, so a valid signature is the gateway's.
    assert len(list(result.valid_sigs)) == 1
    return bytes(result.bytes or b"")


def inbox(owner: Person) -> list[dict[str, Any]]:
    return owner.client.get("/v1/messages", params={"folder": "inbox"}).json()["items"]  # type: ignore[no-any-return]


def open_external(owner: Person, keys: DeviceKeys, message_id: str) -> bytes:
    message = owner.client.get(f"/v1/messages/{message_id}").json()
    assert message["origin"] == "external" and message["sender"] is None
    return decrypt_external(
        owner.client,
        keys,
        base64.b64decode(message["pkesks"][0]),
        base64.b64decode(message["body"]),
    )


def test_external_mail_is_stored_encrypted_for_every_key(
    app: Any, gateway: Gateway, factory: sessionmaker[Session]
) -> None:
    alice = person(app)
    other = second_device(alice, app)
    recovery = register_recovery(alice)
    address = with_address(alice, "alice")

    with smtp(gateway) as client:
        refused = client.sendmail("someone@example.org", [address.upper()], EXTERNAL)
    assert refused == {}

    [item] = inbox(alice)
    assert item["origin"] == "external" and item["sender"] is None
    for owner in (alice, other):  # each active device opens its own copy
        plaintext = open_external(owner, owner.keys, item["id"])
        assert plaintext.endswith(EXTERNAL)
        headers = plaintext[: -len(EXTERNAL)].decode()
        assert headers.startswith("Return-Path: <someone@example.org>\r\nReceived: from ")
        assert f"for <{address.upper()}>" in headers and "[127.0.0.1]" in headers
    message = alice.client.get(f"/v1/messages/{item['id']}").json()
    assert len(message["recovery_pkesks"]) == 1
    plaintext = decrypt_external(
        alice.client,
        recovery,
        base64.b64decode(message["recovery_pkesks"][0]),
        base64.b64decode(message["body"]),
    )
    assert plaintext.endswith(EXTERNAL)

    with factory() as session:  # nothing in clear in the database
        stored = session.scalars(select(Message)).one()
        assert b"TEST-ONLY" not in stored.body and b"someone@example.org" not in stored.body


def test_one_message_per_recipient_account(app: Any, gateway: Gateway) -> None:
    alice, bob = person(app), person(app)
    to_alice, to_bob = with_address(alice, "alice"), with_address(bob, "bob")
    with smtp(gateway) as client:
        assert client.sendmail("someone@example.org", [to_alice, to_bob], EXTERNAL) == {}
    [for_alice], [for_bob] = inbox(alice), inbox(bob)
    assert for_alice["id"] != for_bob["id"]
    assert b"for <bob@" in open_external(bob, bob.keys, for_bob["id"])
    # Alice's devices have no key to Bob's copy.
    assert alice.client.get(f"/v1/messages/{for_bob['id']}").status_code == 404


def test_unknown_recipients_are_refused_and_enumeration_is_limited(
    app: Any, gateway: Gateway, settings: Settings
) -> None:
    alice = person(app)
    address = with_address(alice, "alice")
    with smtp(gateway) as client:
        client.mail("someone@example.org")
        assert client.rcpt(f"nobody@{DOMAIN}")[0] == 550
        assert client.rcpt("alice@elsewhere.example")[0] == 550
        assert client.rcpt(address)[0] == 250
        for i in range(settings.inbound_max_unknown_recipients - 2):
            assert client.rcpt(f"guess{i}@{DOMAIN}")[0] == 550
        assert client.rcpt(f"guess-last@{DOMAIN}")[0] == 421
        with pytest.raises(smtplib.SMTPServerDisconnected):
            client.rcpt(address)
    assert inbox(alice) == []


def test_account_without_devices_gets_a_temporary_error(app: Any, gateway: Gateway) -> None:
    client = TestClient(app, raise_server_exceptions=False)
    login(client)
    assert client.post("/v1/addresses", json={"local_part": "newbie"}).status_code == 201
    with smtp(gateway) as smtp_client:
        smtp_client.mail("someone@example.org")
        assert smtp_client.rcpt(f"newbie@{DOMAIN}")[0] == 450


def test_recipient_and_size_limits(app: Any, gateway: Gateway, settings: Settings) -> None:
    people = [person(app) for _ in range(4)]
    addresses = [with_address(p, f"user{i}") for i, p in enumerate(people)]
    with smtp(gateway) as client:
        client.mail("someone@example.org")
        codes = [client.rcpt(a)[0] for a in addresses]
    assert codes == [250, 250, 250, 452]  # max_message_recipients = 3

    huge = b"Subject: big\r\n\r\n" + b"x" * settings.max_message_bytes + b"\r\n"
    with smtp(gateway) as client, pytest.raises(smtplib.SMTPResponseException) as error:
        client.sendmail("someone@example.org", [addresses[0]], huge)
    assert error.value.smtp_code == 552
    assert inbox(people[0]) == []


def test_failures_are_temporary_and_store_nothing(
    app: Any, gateway: Gateway, factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    alice = person(app)
    address = with_address(alice, "alice")

    def broken(_plaintext: bytes, _certs: list[bytes]) -> Any:
        raise ValueError("TEST-ONLY external body")

    monkeypatch.setattr(delivery, "encrypt_to_certificates", broken)
    with smtp(gateway) as client, pytest.raises(smtplib.SMTPDataError) as error:
        client.sendmail("someone@example.org", [address], EXTERNAL)
    assert error.value.smtp_code == 451
    assert b"TEST-ONLY" not in error.value.smtp_error
    with factory() as session:
        assert session.scalar(select(func.count()).select_from(Message)) == 0


def test_keys_without_a_valid_wallet_attestation_are_skipped(
    app: Any, gateway: Gateway, factory: sessionmaker[Session]
) -> None:
    """A device key written into the database without the wallet gets nothing."""
    alice = person(app)
    forged = second_device(alice, app)
    address = with_address(alice, "alice")
    with factory() as session, session.begin():
        session.execute(
            update(Device)
            .where(Device.id == uuid.UUID(forged.device.device_id))
            .values(certificate_signature="0x" + "11" * 65)
        )
    with smtp(gateway) as client:
        assert client.sendmail("someone@example.org", [address], EXTERNAL) == {}
    [item] = inbox(alice)
    assert open_external(alice, alice.keys, item["id"]).endswith(EXTERNAL)
    assert forged.client.get(f"/v1/messages/{item['id']}").json()["pkesks"] == []


def test_trace_headers_cannot_be_injected() -> None:
    arrival = Arrival(
        content=b"body",
        mail_from="a@b.example\r\nBcc: x",
        helo="evil\r\nX-Injected: 1",
        peer="192.0.2.1",
        hostname=DOMAIN,
        esmtp=True,
        received_at=datetime(2026, 11, 12, tzinfo=UTC),
    )
    rendered = arrival.for_recipient("alice@" + DOMAIN)
    headers = rendered[: -len(b"body")].split(b"\r\n")
    assert all(not line.startswith((b"Bcc", b"X-Injected")) for line in headers)
    assert len([line for line in headers if line and not line.startswith(b"\t")]) == 2


@pytest.mark.parametrize(
    "data",
    [
        b"\x84\x01",  # legacy header
        b"\xd2\xe0abc",  # partial body length
        b"\xd2\x05ab",  # truncated
        b"\xd2",  # header only
    ],
)
def test_split_packets_refuses_unexpected_framing(data: bytes) -> None:
    with pytest.raises(EnvelopeRejectedError):
        split_packets(data)


def test_message_content_and_envelope_never_reach_the_logs(
    app: Any, gateway: Gateway, caplog: pytest.LogCaptureFixture
) -> None:
    alice = person(app)
    address = with_address(alice, "alice")
    caplog.set_level(logging.DEBUG)
    with smtp(gateway) as client:
        assert client.sendmail("someone@example.org", [address], EXTERNAL) == {}
    assert inbox(alice)
    for secret in ("TEST-ONLY", "someone@example.org", address, "hello"):
        assert secret not in caplog.text
