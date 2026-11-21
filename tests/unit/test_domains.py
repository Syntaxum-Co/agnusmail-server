"""Custom domains: TXT verification, addresses, transfer, gateways.

DNS is a dictionary on ``app.state.dns_txt`` (no network in tests).
"""

import secrets
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.apps.smtp_outbound.__main__ import register_queue_key
from agnusmail.modules.addresses.service import resolve
from agnusmail.modules.audit.models import AuditEvent
from agnusmail.modules.outbound.dkim import DkimSigner, generate_dkim_key
from agnusmail.modules.outbound.queue_key import generate_queue_key, load_queue_key
from agnusmail.modules.outbound.sender import OutboundSender
from agnusmail.testing.auth import login
from agnusmail.testing.fakes import make_app, make_session_factory
from agnusmail.testing.people import Person, person
from tests.unit.test_outbound import OUTBOUND, claim, mime, submission
from tests.unit.test_outbound_dkim import receiver_dns
from tests.unit.test_outbound_sender import FakeTransport, QueueKeyAdapter

DOMAINS = "/v1/domains"
SERVICE_DOMAIN = "mail.agnusmail.localhost"


class FakeDns:
    def __init__(self) -> None:
        self.txt: dict[str, list[str]] = {}

    def __call__(self, name: str) -> list[str]:
        return list(self.txt.get(name, []))

    def publish(self, domain: dict[str, Any]) -> None:
        record = domain["records"][0]
        self.txt.setdefault(record["host"], []).append(record["value"])

    def unpublish(self, domain: dict[str, Any]) -> None:
        record = domain["records"][0]
        self.txt[record["host"]].remove(record["value"])


@pytest.fixture
def factory() -> sessionmaker[Session]:
    return make_session_factory()


@pytest.fixture
def dns() -> FakeDns:
    return FakeDns()


@pytest.fixture
def app(factory: sessionmaker[Session], dns: FakeDns) -> Any:
    application = make_app(session_factory=factory)[0]
    application.state.dns_txt = dns
    return application


@pytest.fixture
def alice(app: Any) -> Iterator[Person]:
    p = person(app)
    claim(p)
    yield p
    p.client.close()


def unique_domain() -> str:
    return f"d{secrets.token_hex(4)}.example.com"


def add(owner: Person, name: str) -> dict[str, Any]:
    response = owner.client.post(DOMAINS, json={"name": name})
    assert response.status_code == 201, response.text
    data: dict[str, Any] = response.json()
    return data


def verified(owner: Person, dns: FakeDns, name: str) -> dict[str, Any]:
    domain = add(owner, name)
    dns.publish(domain)
    response = owner.client.post(f"{DOMAINS}/{domain['id']}/verify")
    assert response.status_code == 200, response.text
    data: dict[str, Any] = response.json()
    return data


def address(owner: Person, domain: dict[str, Any], local: str) -> dict[str, Any]:
    response = owner.client.post(f"{DOMAINS}/{domain['id']}/addresses", json={"local_part": local})
    assert response.status_code == 201, response.text
    data: dict[str, Any] = response.json()
    return data


def test_add_lists_the_records_to_publish(alice: Person) -> None:
    name = unique_domain()
    domain = add(alice, name.upper() + ".")
    assert (domain["name"], domain["status"]) == (name, "pending")
    kinds = [(r["type"], r["host"]) for r in domain["records"]]
    assert kinds[0] == ("TXT", f"_agnusmail.{name}")
    assert domain["records"][0]["value"].startswith("agnusmail-verification=")
    assert ("CNAME", f"agnus1._domainkey.{name}") in kinds
    spf = next(r for r in domain["records"] if r["purpose"] == "SPF")
    assert spf["value"] == f"v=spf1 include:{SERVICE_DOMAIN} -all"


@pytest.mark.parametrize(
    "name", ["localhost", "exa_mple.com", "ção.com.br", SERVICE_DOMAIN, f"x.{SERVICE_DOMAIN}"]
)
def test_invalid_or_service_domains_are_refused(alice: Person, name: str) -> None:
    assert alice.client.post(DOMAINS, json={"name": name}).status_code == 422


def test_limits_and_duplicates(alice: Person) -> None:
    first = unique_domain()
    add(alice, first)
    assert alice.client.post(DOMAINS, json={"name": first}).status_code == 409
    add(alice, unique_domain())
    add(alice, unique_domain())
    assert alice.client.post(DOMAINS, json={"name": unique_domain()}).status_code == 409


def test_verification_needs_the_txt_record(
    alice: Person, dns: FakeDns, factory: sessionmaker[Session]
) -> None:
    domain = add(alice, unique_domain())
    missing = alice.client.post(f"{DOMAINS}/{domain['id']}/verify")
    assert missing.status_code == 409
    assert missing.json()["error"]["code"] == "DOMAIN_NOT_VERIFIED"
    dns.publish(domain)
    done = alice.client.post(f"{DOMAINS}/{domain['id']}/verify").json()
    assert done["status"] == "verified" and done["verified_at"]
    with factory() as session:
        types = session.scalars(
            select(AuditEvent.event_type).where(AuditEvent.event_type.like("domain.%"))
        ).all()
        assert sorted(types) == ["domain.added", "domain.verified"]


def test_domain_addresses_resolve_and_follow_the_rules(
    alice: Person, dns: FakeDns, factory: sessionmaker[Session]
) -> None:
    name = unique_domain()
    domain = add(alice, name)
    early = alice.client.post(f"{DOMAINS}/{domain['id']}/addresses", json={"local_part": "joao"})
    assert early.status_code == 409  # not verified yet
    dns.publish(domain)
    alice.client.post(f"{DOMAINS}/{domain['id']}/verify")
    created = address(alice, domain, "Postmaster")  # reserved names are the owner's here
    assert (created["email"], created["kind"]) == (f"postmaster@{name}", "domain")
    lookalike = alice.client.post(
        f"{DOMAINS}/{domain['id']}/addresses", json={"local_part": "p0stmaster"}
    )
    assert lookalike.status_code == 409
    resolved = alice.client.get(f"/v1/directory/addresses/postmaster@{name.upper()}")
    assert resolved.json()["account"] == alice.user.address.lower()
    with factory() as session:
        _, user = resolve(session, f"postmaster@{name}", SERVICE_DOMAIN)
        assert str(user.id) == alice.user.user_id


def test_domain_changes_hands_only_when_the_old_txt_is_gone(
    app: Any, alice: Person, dns: FakeDns, factory: sessionmaker[Session]
) -> None:
    name = unique_domain()
    first = verified(alice, dns, name)
    address(alice, first, "joao")
    bob = person(app)
    claim(bob)
    second = add(bob, name)
    dns.publish(second)
    taken = bob.client.post(f"{DOMAINS}/{second['id']}/verify")
    assert taken.status_code == 409
    assert taken.json()["error"]["code"] == "DOMAIN_TAKEN"

    dns.unpublish(first)  # alice no longer controls the DNS
    moved = bob.client.post(f"{DOMAINS}/{second['id']}/verify")
    assert moved.json()["status"] == "verified"
    assert alice.client.get(DOMAINS).json()["items"][0]["status"] == "pending"
    emails = [a["email"] for a in alice.client.get("/v1/addresses").json()["items"]]
    assert f"joao@{name}" not in emails
    # The new owner can use the same name.
    address(bob, second, "joao")
    assert bob.client.get(f"/v1/directory/addresses/joao@{name}").json()["account"] == (
        bob.user.address.lower()
    )
    with factory() as session:
        lost = session.scalars(
            select(AuditEvent).where(AuditEvent.event_type == "domain.lost")
        ).one()
        assert str(lost.user_id) == alice.user.user_id and lost.actor_user_id is None
    bob.client.close()


def test_removing_a_domain_drops_its_addresses(alice: Person, dns: FakeDns) -> None:
    name = unique_domain()
    domain = verified(alice, dns, name)
    address(alice, domain, "joao")
    assert alice.client.delete(f"{DOMAINS}/{domain['id']}").status_code == 204
    assert alice.client.get(f"/v1/directory/addresses/joao@{name}").status_code == 404
    assert alice.client.get(DOMAINS).json()["items"] == []


def test_domains_are_private(app: Any, alice: Person) -> None:
    domain = add(alice, unique_domain())
    with TestClient(app, raise_server_exceptions=False) as other:
        login(other)
        assert other.get(DOMAINS).json()["items"] == []
        assert other.post(f"{DOMAINS}/{domain['id']}/verify").status_code == 404
        assert other.delete(f"{DOMAINS}/{domain['id']}").status_code == 404
        response = other.post(f"{DOMAINS}/{domain['id']}/addresses", json={"local_part": "x1x"})
        assert response.status_code == 404


def test_hosted_domains_are_internal_for_outbound(
    alice: Person, dns: FakeDns, factory: sessionmaker[Session]
) -> None:
    from tests.unit.test_outbound import register_outbound_key

    queue = register_outbound_key(factory)
    name = unique_domain()
    verified(alice, dns, name)
    sender = alice.client.get("/v1/addresses").json()["items"][0]["email"]
    response = alice.client.post(
        OUTBOUND, json=submission(queue, mime(sender), [f"someone@{name}"])
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "RECIPIENT_INTERNAL"


def test_sending_from_a_custom_domain_signs_with_its_d(
    alice: Person, dns: FakeDns, factory: sessionmaker[Session]
) -> None:
    key = load_queue_key(generate_queue_key(), now=datetime.now(UTC))
    with factory() as session, session.begin():
        register_queue_key(session, key)
    name = unique_domain()
    domain = verified(alice, dns, name)
    own = address(alice, domain, "ceo")["email"]
    payload = submission(QueueKeyAdapter(key), mime(own), ["partner@example.org"], sender=own)
    assert alice.client.post(OUTBOUND, json=payload).status_code == 202
    pem = generate_dkim_key()
    transport = FakeTransport()
    OutboundSender(
        factory,
        keys=[key],
        signer=DkimSigner(SERVICE_DOMAIN, "agnus1", pem),
        transport=transport,
        mail_domain=SERVICE_DOMAIN,
    ).run_once(datetime.now(UTC))
    data = transport.calls[0][3]
    assert f"d={name}".encode() in data
    # Through the CNAME the receiver finds our key under the custom domain.
    import dkim

    assert dkim.verify(data, dnsfunc=receiver_dns(pem, domain=name))
