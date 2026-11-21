"""SMTP delivery to the recipient's server, against a local test MTA."""

import smtplib
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import dns.exception
import dns.resolver
import pytest

from agnusmail.modules.inbound.smtp import build_tls_context
from agnusmail.modules.outbound.delivery import (
    DnsResolver,
    Outcome,
    PermanentDnsError,
    Result,
    SmtpDelivery,
    TemporaryDnsError,
    is_public,
)
from tests.outbound_helpers import FakeResolver, TestMta
from tests.unit.test_inbound import free_port
from tests.unit.test_inbound_connections import self_signed

DATA = b"From: a@mail.example.com\r\nTo: b@example.org\r\n\r\n.leading dot\r\nbody\r\n"
PUBLIC_1, PUBLIC_2 = "93.184.216.1", "93.184.216.2"


@pytest.fixture
def mta() -> Iterator[TestMta]:
    server = TestMta()
    server.start()
    yield server
    server.stop()


def via_relay(mta: TestMta, **options: Any) -> SmtpDelivery:
    return SmtpDelivery(
        hostname="out.mail.example.com", resolver=FakeResolver(), relay=mta.relay, **options
    )


def routed(mapping: dict[str, int]) -> Any:
    """Connect to a 'public' IP by sending it to a local port instead."""

    def connect(host: str, port: int, **options: Any) -> smtplib.SMTP:
        return smtplib.SMTP("127.0.0.1", mapping[host], **options)

    return connect


def test_delivers_and_keeps_only_codes(mta: TestMta) -> None:
    results = via_relay(mta).deliver(
        "example.org", "a@mail.example.com", ["b@example.org", "c@example.org"], DATA
    )
    assert results == dict.fromkeys(
        ["b@example.org", "c@example.org"], Result(Outcome.DELIVERED, 250, "2.0.0")
    )
    received = mta.recorder.received[0]
    assert received.mail_from == "a@mail.example.com"
    assert received.recipients == ["b@example.org", "c@example.org"]
    assert received.content == DATA  # dot-stuffing undone on the other side


def test_per_recipient_outcomes(mta: TestMta) -> None:
    results = via_relay(mta).deliver(
        "example.org",
        "a@mail.example.com",
        ["ok@example.org", "reject@example.org", "later@example.org"],
        DATA,
    )
    assert results["ok@example.org"] == Result(Outcome.DELIVERED, 250, "2.0.0")
    assert results["reject@example.org"] == Result(Outcome.FAILED, 550, "5.1.1")
    assert results["later@example.org"] == Result(Outcome.RETRY, 451, "4.2.0")
    assert mta.recorder.received[0].recipients == ["ok@example.org"]


def test_nobody_accepted_sends_no_data(mta: TestMta) -> None:
    results = via_relay(mta).deliver("example.org", "a@x.org", ["reject@example.org"], DATA)
    assert results["reject@example.org"].outcome is Outcome.FAILED
    assert mta.recorder.received == []


@pytest.mark.parametrize(
    ("reply", "outcome"),
    [("554 5.6.0 refused", Outcome.FAILED), ("452 4.3.1 full", Outcome.RETRY)],
)
def test_data_reply_applies_to_accepted_recipients(
    mta: TestMta, reply: str, outcome: Outcome
) -> None:
    mta.recorder.data_reply = reply
    results = via_relay(mta).deliver("example.org", "a@x.org", ["b@example.org"], DATA)
    assert results["b@example.org"].outcome is outcome
    assert results["b@example.org"].code == int(reply[:3])


def test_unreachable_server_is_retried() -> None:
    closed = free_port()
    delivery = SmtpDelivery(
        hostname="out.example.com", resolver=FakeResolver(), relay=("127.0.0.1", closed)
    )
    results = delivery.deliver("example.org", "a@x.org", ["b@example.org"], DATA)
    assert results["b@example.org"] == Result(Outcome.RETRY, None, "connection_failed")


def test_starttls_is_used_when_offered(tmp_path: Path) -> None:
    server = TestMta(tls=build_tls_context(*self_signed(tmp_path)))
    server.start()
    try:
        results = via_relay(server, require_tls=True).deliver(
            "example.org", "a@x.org", ["b@example.org"], DATA
        )
    finally:
        server.stop()
    assert results["b@example.org"].outcome is Outcome.DELIVERED
    assert server.recorder.received[0].tls


def test_required_tls_refuses_plain_servers(mta: TestMta) -> None:
    results = via_relay(mta, require_tls=True).deliver(
        "example.org", "a@x.org", ["b@example.org"], DATA
    )
    assert results["b@example.org"] == Result(Outcome.RETRY, None, "tls_unavailable")
    assert mta.recorder.received == []


def test_mx_hosts_in_order_falls_back_to_the_next(mta: TestMta) -> None:
    resolver = FakeResolver(
        mx={"example.org": ["mx1.example.org", "mx2.example.org"]},
        a={"mx1.example.org": [PUBLIC_1], "mx2.example.org": [PUBLIC_2]},
    )
    delivery = SmtpDelivery(
        hostname="out.example.com",
        resolver=resolver,
        connect=routed({PUBLIC_1: free_port(), PUBLIC_2: mta.port}),
    )
    results = delivery.deliver("example.org", "a@x.org", ["b@example.org"], DATA)
    assert results["b@example.org"].outcome is Outcome.DELIVERED


def test_private_mx_is_never_contacted() -> None:
    contacted: list[str] = []

    def connect(host: str, *_args: Any, **_kw: Any) -> smtplib.SMTP:
        contacted.append(host)
        raise OSError("must not connect")

    resolver = FakeResolver(
        mx={"evil.example": ["mx.evil.example"]},
        a={"mx.evil.example": ["10.0.0.5", "127.0.0.1", "169.254.169.254", "::1"]},
    )
    delivery = SmtpDelivery(hostname="out.example.com", resolver=resolver, connect=connect)
    results = delivery.deliver("evil.example", "a@x.org", ["b@evil.example"], DATA)
    assert results["b@evil.example"] == Result(Outcome.FAILED, None, "no_public_address")
    assert contacted == []


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (PermanentDnsError("nxdomain"), Result(Outcome.FAILED, None, "dns_nxdomain")),
        (PermanentDnsError("null_mx"), Result(Outcome.FAILED, None, "dns_null_mx")),
        (TemporaryDnsError(), Result(Outcome.RETRY, None, "dns_temporary")),
    ],
)
def test_dns_outcomes(error: Exception, expected: Result) -> None:
    delivery = SmtpDelivery(
        hostname="out.example.com", resolver=FakeResolver(errors={"example.org": error})
    )
    assert delivery.deliver("example.org", "a@x.org", ["b@example.org"], DATA) == {
        "b@example.org": expected
    }


def test_is_public() -> None:
    assert is_public("93.184.216.34") and is_public("2606:4700::1111")
    for address in ("10.1.2.3", "192.168.0.1", "127.0.0.1", "::1", "fe80::1", "100.64.0.1", "x"):
        assert not is_public(address)


class FakeDns:
    def __init__(self, answers: dict[tuple[str, str], Any]) -> None:
        self.answers = answers

    def resolve(self, name: str, rdtype: str, lifetime: float) -> list[Any]:
        answer = self.answers.get((name, rdtype), dns.resolver.NoAnswer())  # type: ignore[no-untyped-call]
        if isinstance(answer, Exception):
            raise answer
        return list(answer)


def resolver_with(answers: dict[tuple[str, str], Any]) -> DnsResolver:
    resolver = DnsResolver()
    resolver._resolver = FakeDns(answers)  # type: ignore[assignment]
    return resolver


def mx(preference: int, exchange: str) -> Any:
    return SimpleNamespace(preference=preference, exchange=exchange)


def test_dns_resolver_orders_mx_by_preference() -> None:
    resolver = resolver_with(
        {("example.org", "MX"): [mx(20, "b.example.org."), mx(10, "A.example.org.")]}
    )
    assert resolver.mail_hosts("example.org") == ["a.example.org", "b.example.org"]


def test_dns_resolver_implicit_null_and_errors() -> None:
    assert resolver_with({}).mail_hosts("example.org") == ["example.org"]
    with pytest.raises(PermanentDnsError, match="null_mx"):
        resolver_with({("example.org", "MX"): [mx(0, ".")]}).mail_hosts("example.org")
    nxdomain = dns.resolver.NXDOMAIN()  # type: ignore[no-untyped-call]
    with pytest.raises(PermanentDnsError, match="nxdomain"):
        resolver_with({("example.org", "MX"): nxdomain}).mail_hosts("example.org")
    timeout = dns.exception.Timeout()  # type: ignore[no-untyped-call]
    with pytest.raises(TemporaryDnsError):
        resolver_with({("example.org", "MX"): timeout}).mail_hosts("example.org")


def test_dns_resolver_addresses() -> None:
    resolver = resolver_with(
        {
            ("mx.example.org", "A"): [SimpleNamespace(address="93.184.216.34")],
            ("mx.example.org", "AAAA"): [SimpleNamespace(address="2606:4700::1")],
        }
    )
    assert resolver.addresses("mx.example.org") == ["2606:4700::1", "93.184.216.34"]
    assert resolver_with({}).addresses("none.example.org") == []


def test_socket_errors_are_temporary() -> None:
    def connect(*_args: Any, **_kw: Any) -> smtplib.SMTP:
        raise TimeoutError("slow")

    resolver = FakeResolver(a={"example.org": [PUBLIC_1]})
    delivery = SmtpDelivery(hostname="out.example.com", resolver=resolver, connect=connect)
    results = delivery.deliver("example.org", "a@x.org", ["b@example.org"], DATA)
    assert results["b@example.org"].outcome is Outcome.RETRY
