"""The Rspamd client against a real Rspamd with the project's configuration.

Runs when AGNUSMAIL_TEST_RSPAMD_URL points at it (dev compose service ``rspamd``; CI
starts one). Results depend on live DNS (SPF/DMARC of example.org), so only the
protocol and the configured behavior are asserted, not a score.
"""

import os

import pytest

from agnusmail.modules.inbound.antispam import Action, RspamdScanner, ScanRequest

pytestmark = pytest.mark.integration

URL = os.environ.get("AGNUSMAIL_TEST_RSPAMD_URL")
MESSAGE = (
    b"From: Someone <someone@example.org>\r\n"
    b"To: alice@mail.agnusmail.test\r\n"
    b"Subject: hello\r\n"
    b"Message-ID: <test-1@example.org>\r\n"
    b"Date: Fri, 13 Nov 2026 10:00:00 +0000\r\n"
    b"Authentication-Results: mx.agnus.test; spf=pass (forged by the sender)\r\n"
    b"\r\n"
    b"TEST-ONLY body\r\n"
)


@pytest.mark.skipif(URL is None, reason="AGNUSMAIL_TEST_RSPAMD_URL not set")
def test_real_rspamd_scan() -> None:
    assert URL is not None
    result = RspamdScanner(URL, 60).scan(
        ScanRequest(
            content=MESSAGE,
            peer="192.0.2.10",
            helo="mx.example.org",
            mail_from="someone@example.org",
            recipients=["alice@mail.agnusmail.test"],
            hostname="mx.agnus.test",
        )
    )
    assert isinstance(result.action, Action)
    assert result.authentication_results is not None
    assert result.authentication_results.startswith(b"mx.agnus.test;")
    assert b"smtp.mailfrom=someone@example.org" in result.authentication_results
    # Rspamd asks to drop incoming copies of the fields only the gateway may write.
    assert "authentication-results" in result.remove_headers


@pytest.mark.skipif(URL is None, reason="AGNUSMAIL_TEST_RSPAMD_URL not set")
def test_gateway_with_real_rspamd_end_to_end() -> None:
    """SMTP in, real Rspamd, encryption, and the device reads Authentication-Results."""
    from datetime import UTC, datetime

    from agnusmail.infrastructure.openpgp import generate_gateway_key, load_gateway_key
    from agnusmail.modules.inbound.delivery import GatewayContext, register_gateway_key
    from agnusmail.modules.inbound.smtp import InboundHandler
    from tests.unit.fakes import make_app, make_session_factory, make_settings
    from tests.unit.test_inbound import DOMAIN, Gateway, inbox, open_external, smtp, with_address
    from tests.unit.test_messages import person

    assert URL is not None
    settings = make_settings(mail_domain=DOMAIN)
    factory = make_session_factory()
    app = make_app(settings, factory)[0]
    key = load_gateway_key(generate_gateway_key(), now=datetime.now(UTC))
    with factory() as session, session.begin():
        register_gateway_key(session, key)
    handler = InboundHandler(
        factory, GatewayContext.from_settings(settings, key), settings, RspamdScanner(URL, 60)
    )
    gateway = Gateway(handler, settings)
    gateway.start()
    try:
        alice = person(app)
        address = with_address(alice, "alice")
        message = MESSAGE.replace(b"alice@mail.agnusmail.test", address.encode())
        with smtp(gateway) as client:
            client.mail("someone@example.org")
            client.rcpt(address)
            code, _ = client.data(message)
        assert code in (250, 550), code  # 550 only if Rspamd scored it as reject
        if code == 250:
            plaintext = open_external(alice, alice.keys, inbox(alice)[0]["id"])
            head = plaintext.split(b"\r\n\r\n", 1)[0]
            assert head.count(b"Authentication-Results:") == 1  # the forged one is gone
            assert f"Authentication-Results: {DOMAIN};".encode() in head  # results or "none"
            assert b"(forged by the sender)" not in head
    finally:
        gateway.stop()
