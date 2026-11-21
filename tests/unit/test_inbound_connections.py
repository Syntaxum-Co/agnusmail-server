"""Inbound gateway connections: STARTTLS, connection caps and lifetime."""

import smtplib
import socket
import ssl
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from aiosmtpd.smtp import SMTP
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.core.config import Settings
from agnusmail.infrastructure.openpgp import GatewayKey
from agnusmail.infrastructure.redis.rate_limit import RateLimiter
from agnusmail.modules.inbound.delivery import GatewayContext, register_gateway_key
from agnusmail.modules.inbound.smtp import InboundHandler, build_smtp, build_tls_context
from tests.unit.fakes import FakeAsyncRedis, make_app, make_session_factory, make_settings
from tests.unit.test_inbound import (
    DOMAIN,
    EXTERNAL,
    Gateway,
    inbox,
    open_external,
    signing_key,  # noqa: F401  (fixture)
    with_address,
)
from tests.unit.test_messages import person


class TlsGateway(Gateway):
    def __init__(
        self, handler: InboundHandler, settings: Settings, tls: ssl.SSLContext | None
    ) -> None:
        super().__init__(handler, settings)
        self.tls = tls

    def factory(self) -> SMTP:
        return build_smtp(self.handler, self.settings, self.tls)


def self_signed(tmp_path: Path) -> tuple[Path, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, DOMAIN)])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(DOMAIN)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_file, key_file = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_file, key_file


@contextmanager
def running(
    settings: Settings,
    factory: sessionmaker[Session],
    key: GatewayKey,
    tls: ssl.SSLContext | None = None,
    rates: RateLimiter | None = None,
) -> Iterator[TlsGateway]:
    with factory() as session, session.begin():
        register_gateway_key(session, key)
    ctx = GatewayContext.from_settings(settings, key)
    handler = InboundHandler(factory, ctx, settings, None, rates)
    gateway = TlsGateway(handler, settings, tls)
    gateway.start()
    try:
        yield gateway
    finally:
        gateway.stop()


def client_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # self-signed test certificate
    return context


def test_starttls_is_offered_and_recorded(tmp_path: Path, signing_key: GatewayKey) -> None:  # noqa: F811
    settings = make_settings(mail_domain=DOMAIN)
    factory = make_session_factory()
    app = make_app(settings, factory)[0]
    tls = build_tls_context(*self_signed(tmp_path))
    assert tls.minimum_version == ssl.TLSVersion.TLSv1_2
    with running(settings, factory, signing_key, tls) as gateway:
        alice = person(app)
        address = with_address(alice, "alice")
        with smtplib.SMTP(gateway.hostname, gateway.port, timeout=10) as client:
            client.ehlo("mx.example.org")
            assert client.has_extn("starttls")
            client.starttls(context=client_context())
            client.ehlo("mx.example.org")
            cipher = client.sock.version()  # type: ignore[union-attr]
            assert cipher in ("TLSv1.2", "TLSv1.3")
            assert client.sendmail("someone@example.org", [address], EXTERNAL) == {}
        with smtplib.SMTP(gateway.hostname, gateway.port, timeout=10) as plain:
            plain.ehlo("mx.example.org")  # TLS is offered, never required (RFC 3207 §4)
            assert plain.sendmail("someone@example.org", [address], EXTERNAL) == {}
    first, second = sorted(inbox(alice), key=lambda item: str(item["created_at"]))
    assert b"with ESMTPS" in open_external(alice, alice.keys, first["id"])
    assert b"with ESMTP\r\n" in open_external(alice, alice.keys, second["id"])


def connect(gateway: TlsGateway) -> smtplib.SMTP:
    return smtplib.SMTP(gateway.hostname, gateway.port, timeout=10)


def test_connections_per_ip_are_capped(signing_key: GatewayKey) -> None:  # noqa: F811
    settings = make_settings(mail_domain=DOMAIN, inbound_max_connections_per_ip=2)
    with running(settings, make_session_factory(), signing_key) as gateway:
        first, second = connect(gateway), connect(gateway)
        with pytest.raises(smtplib.SMTPConnectError) as refused:
            connect(gateway)
        assert refused.value.smtp_code == 421
        first.quit()
        time.sleep(0.2)  # the server notices the closed connection
        third = connect(gateway)  # a slot is free again
        assert third.noop()[0] == 250
        for client in (second, third):
            client.quit()


def test_total_connections_are_capped(signing_key: GatewayKey) -> None:  # noqa: F811
    settings = make_settings(mail_domain=DOMAIN, inbound_max_connections=1)
    with running(settings, make_session_factory(), signing_key) as gateway:
        only = connect(gateway)
        with pytest.raises(smtplib.SMTPConnectError):
            connect(gateway)
        only.quit()


def test_connection_lifetime_is_capped(signing_key: GatewayKey) -> None:  # noqa: F811
    """A sender that keeps the connection busy (resetting the idle timer) still loses it."""
    settings = make_settings(mail_domain=DOMAIN, inbound_max_connection_seconds=1)
    with running(settings, make_session_factory(), signing_key) as gateway:
        client = connect(gateway)
        deadline = time.monotonic() + 5
        with pytest.raises(smtplib.SMTPServerDisconnected):
            while time.monotonic() < deadline:
                client.noop()
                time.sleep(0.1)
        client.close()


def test_commands_have_call_limits(signing_key: GatewayKey) -> None:  # noqa: F811
    settings = make_settings(mail_domain=DOMAIN)
    with running(settings, make_session_factory(), signing_key) as gateway:
        client = connect(gateway)
        codes: list[int] = []
        with pytest.raises(smtplib.SMTPServerDisconnected):
            for _ in range(200):
                codes.append(client.noop()[0])
        assert codes[-1] == 421 and codes.count(250) == 100
        client.close()


def test_unknown_recipients_are_limited_across_connections(signing_key: GatewayKey) -> None:  # noqa: F811
    settings = make_settings(mail_domain=DOMAIN, inbound_unknown_recipients_per_ip_per_hour=3)
    rates = RateLimiter(FakeAsyncRedis())
    with running(settings, make_session_factory(), signing_key, rates=rates) as gateway:
        with connect(gateway) as first:
            first.ehlo("mx.example.org")
            first.mail("someone@example.org")
            assert [first.rcpt(f"guess{i}@{DOMAIN}")[0] for i in range(2)] == [550, 550]
        with connect(gateway) as second:  # a new connection does not reset the budget
            second.ehlo("mx.example.org")
            second.mail("someone@example.org")
            assert second.rcpt(f"guess2@{DOMAIN}")[0] == 550
            assert second.rcpt(f"guess3@{DOMAIN}")[0] == 421


def test_messages_are_limited_per_ip(signing_key: GatewayKey) -> None:  # noqa: F811
    settings = make_settings(mail_domain=DOMAIN, inbound_messages_per_ip_per_hour=1)
    factory = make_session_factory()
    app = make_app(settings, factory)[0]
    rates = RateLimiter(FakeAsyncRedis())
    with running(settings, factory, signing_key, rates=rates) as gateway:
        alice = person(app)
        address = with_address(alice, "alice")
        with connect(gateway) as client:
            client.ehlo("mx.example.org")
            assert client.sendmail("someone@example.org", [address], EXTERNAL) == {}
            with pytest.raises(smtplib.SMTPDataError) as error:
                client.sendmail("someone@example.org", [address], EXTERNAL)
    assert error.value.smtp_code == 451 and b"Too many messages" in error.value.smtp_error
    assert len(inbox(alice)) == 1


class BrokenRedis:
    def pipeline(self, transaction: bool = True) -> "BrokenRedis":
        raise ConnectionError("redis down")


def test_limits_fail_open_when_redis_is_down(signing_key: GatewayKey) -> None:  # noqa: F811
    settings = make_settings(mail_domain=DOMAIN, inbound_messages_per_ip_per_hour=1)
    factory = make_session_factory()
    app = make_app(settings, factory)[0]
    with running(settings, factory, signing_key, rates=RateLimiter(BrokenRedis())) as gateway:
        alice = person(app)
        address = with_address(alice, "alice")
        with connect(gateway) as client:
            client.ehlo("mx.example.org")
            for _ in range(2):
                assert client.sendmail("someone@example.org", [address], EXTERNAL) == {}
    assert len(inbox(alice)) == 2


def proxied(gateway: TlsGateway, header: bytes) -> smtplib.SMTP:
    """A load balancer's connection: the PROXY header first, then plain SMTP."""
    sock = socket.create_connection((gateway.hostname, gateway.port), timeout=10)
    sock.sendall(header)
    client = smtplib.SMTP()
    client.sock = sock
    code, _ = client.getreply()
    if code != 220:
        raise smtplib.SMTPConnectError(code, b"no greeting")
    return client


PROXY_V1 = b"PROXY TCP4 198.51.100.7 192.0.2.25 40000 25\r\n"


def test_proxy_protocol_gives_the_real_client_ip(signing_key: GatewayKey) -> None:  # noqa: F811
    settings = make_settings(
        mail_domain=DOMAIN,
        inbound_proxy_protocol=True,
        inbound_proxy_timeout_seconds=1,
        inbound_trusted_proxies=["127.0.0.0/8"],
    )
    factory = make_session_factory()
    app = make_app(settings, factory)[0]
    redis = FakeAsyncRedis()
    with running(settings, factory, signing_key, rates=RateLimiter(redis)) as gateway:
        alice = person(app)
        address = with_address(alice, "alice")
        client = proxied(gateway, PROXY_V1)
        client.ehlo("mx.example.org")
        assert client.sendmail("someone@example.org", [address], EXTERNAL) == {}
        client.quit()
    plaintext = open_external(alice, alice.keys, inbox(alice)[0]["id"])
    assert b"([198.51.100.7])" in plaintext  # not the proxy's 127.0.0.1
    assert any("198.51.100.7" in key for key in redis.store)  # limits use the real IP


@pytest.mark.parametrize(
    ("trusted", "header"),
    [
        (["10.0.0.0/8"], PROXY_V1),  # PROXY header from an untrusted peer
        (["127.0.0.0/8"], b"EHLO mx.example.org\r\n"),  # no PROXY header at all
        (["127.0.0.0/8"], b"PROXY TCP4 not-an-ip 192.0.2.25 1 25\r\n"),  # malformed
    ],
)
def test_untrusted_or_missing_proxy_headers_are_refused(
    signing_key: GatewayKey,  # noqa: F811
    trusted: list[str],
    header: bytes,
) -> None:
    settings = make_settings(
        mail_domain=DOMAIN,
        inbound_proxy_protocol=True,
        inbound_proxy_timeout_seconds=1,
        inbound_trusted_proxies=trusted,
    )
    with running(settings, make_session_factory(), signing_key) as gateway:
        with pytest.raises((smtplib.SMTPServerDisconnected, smtplib.SMTPConnectError)):
            proxied(gateway, header)


class Recorder:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, object]]] = []

    def __getattr__(self, _level: str) -> object:
        return lambda event, **fields: self.events.append((event, fields))


def test_non_public_client_ip_is_reported_once(
    signing_key: GatewayKey,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Outside local (warn_non_public is set from the environment), once per process."""
    from agnusmail.modules.inbound import smtp as smtp_module

    recorder = Recorder()
    monkeypatch.setattr(smtp_module, "log", recorder)
    settings = make_settings(mail_domain=DOMAIN)
    factory = make_session_factory()
    app = make_app(settings, factory)[0]
    with running(settings, factory, signing_key) as gateway:
        assert gateway.handler.warn_non_public is False  # local environment: no warning
        gateway.handler.warn_non_public = True  # as in staging/production
        alice = person(app)
        address = with_address(alice, "alice")
        with connect(gateway) as client:
            client.ehlo("mx.example.org")
            for _ in range(2):
                assert client.sendmail("someone@example.org", [address], EXTERNAL) == {}
    warnings = [f for e, f in recorder.events if e == "inbound_client_ip_not_public"]
    assert len(warnings) == 1 and "127.0.0.1" not in str(warnings[0])
