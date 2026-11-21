"""Antispam before encryption: gateway decisions and the Rspamd client."""

import json
import smtplib
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.core.config import Settings
from agnusmail.infrastructure.openpgp import GatewayKey
from agnusmail.modules.inbound.antispam import (
    Action,
    RspamdScanner,
    ScannerUnavailableError,
    ScanRequest,
    ScanResult,
    parse_reply,
    strip_header_fields,
)
from agnusmail.modules.inbound.delivery import GatewayContext, register_gateway_key
from agnusmail.modules.inbound.smtp import InboundHandler
from agnusmail.modules.messages.models import Message
from tests.unit.test_inbound import (
    EXTERNAL,
    Gateway,
    app,  # noqa: F401  (fixture)
    factory,  # noqa: F401  (fixture)
    inbox,
    open_external,
    settings,  # noqa: F401  (fixture)
    signing_key,  # noqa: F401  (fixture)
    smtp,
    with_address,
)
from tests.unit.test_messages import person

AUTH_RESULTS = b"mx.agnus.test;\r\n\tdkim=none;\r\n\tspf=pass smtp.mailfrom=someone@example.org"
FORGED = (
    b"Authentication-Results: mx.agnus.test; spf=pass; dkim=pass\r\n"
    b"X-Spam: No\r\n"
    b"X-Spam-Score: -10\r\n"
    b"X-Forged-By-Sender: keep me\r\n"
)


class FakeScanner:
    def __init__(self, result: ScanResult | Exception) -> None:
        self.result = result
        self.requests: list[ScanRequest] = []

    def scan(self, request: ScanRequest) -> ScanResult:
        self.requests.append(request)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def verdict(action: Action, score: float = 1.0) -> ScanResult:
    return ScanResult(action, score, AUTH_RESULTS, frozenset({"x-spam"}))


@pytest.fixture
def scanner() -> FakeScanner:
    return FakeScanner(verdict(Action.ACCEPT))


@pytest.fixture
def gateway(
    settings: Settings,  # noqa: F811
    factory: sessionmaker[Session],  # noqa: F811
    signing_key: GatewayKey,  # noqa: F811
    scanner: FakeScanner,
) -> Iterator[Gateway]:
    with factory() as session, session.begin():
        register_gateway_key(session, signing_key)
    ctx = GatewayContext.from_settings(settings, signing_key)
    controller = Gateway(InboundHandler(factory, ctx, settings, scanner), settings)
    controller.start()
    yield controller
    controller.stop()


def deliver_one(app: Any, gateway: Gateway, message: bytes = EXTERNAL) -> tuple[Any, str]:  # noqa: F811
    alice = person(app)
    address = with_address(alice, "alice")
    with smtp(gateway) as client:
        assert client.sendmail("someone@example.org", [address], message) == {}
    return alice, address


def test_scan_sees_the_envelope_and_results_go_inside_the_ciphertext(
    app: Any,  # noqa: F811
    gateway: Gateway,
    scanner: FakeScanner,
) -> None:
    alice, address = deliver_one(app, gateway, FORGED + EXTERNAL)
    [request] = scanner.requests
    assert request.content == FORGED + EXTERNAL  # scanned before anything was added
    assert (request.peer, request.helo, request.mail_from) == (
        "127.0.0.1",
        "mx.example.org",
        "someone@example.org",
    )
    assert request.recipients == [address] and request.hostname == gateway.settings.mail_domain

    [item] = inbox(alice)
    plaintext = open_external(alice, alice.keys, item["id"])
    head = plaintext.split(b"\r\n\r\n", 1)[0].split(b"\r\n")
    assert head[0].startswith(b"Return-Path: ")
    assert head[1:5] == [
        b"Authentication-Results: mx.agnus.test;",
        b"\tdkim=none;",
        b"\tspf=pass smtp.mailfrom=someone@example.org",
        b"X-Spam: No",
    ]
    assert b"X-Spam-Score: 1.00" in head and b"X-Forged-By-Sender: keep me" in head
    # The sender's forged verdicts are gone: only the gateway's remain.
    assert sum(line.startswith(b"Authentication-Results") for line in head) == 1
    assert sum(line.startswith(b"X-Spam:") for line in head) == 1
    assert b"X-Spam-Score: -10" not in plaintext


@pytest.mark.parametrize(
    ("action", "code"),
    [(Action.REJECT, 550), (Action.SOFT_REJECT, 451), (Action.GREYLIST, 451)],
)
def test_refused_messages_store_nothing(
    app: Any,  # noqa: F811
    gateway: Gateway,
    scanner: FakeScanner,
    factory: sessionmaker[Session],  # noqa: F811
    action: Action,
    code: int,
) -> None:
    scanner.result = verdict(action, 20.0)
    alice = person(app)
    address = with_address(alice, "alice")
    with smtp(gateway) as client, pytest.raises(smtplib.SMTPDataError) as error:
        client.sendmail("someone@example.org", [address], EXTERNAL)
    assert error.value.smtp_code == code
    with factory() as session:
        assert session.scalar(select(func.count()).select_from(Message)) == 0


def test_spam_is_kept_and_marked(app: Any, gateway: Gateway, scanner: FakeScanner) -> None:  # noqa: F811
    scanner.result = verdict(Action.ADD_HEADER, 9.5)
    alice, _ = deliver_one(app, gateway)
    plaintext = open_external(alice, alice.keys, inbox(alice)[0]["id"])
    assert b"\r\nX-Spam: Yes\r\nX-Spam-Score: 9.50\r\n" in plaintext


def test_scanner_failure_is_a_temporary_error(
    app: Any,  # noqa: F811
    gateway: Gateway,
    scanner: FakeScanner,
    factory: sessionmaker[Session],  # noqa: F811
) -> None:
    scanner.result = ScannerUnavailableError("ConnectionRefusedError")
    alice = person(app)
    address = with_address(alice, "alice")
    with smtp(gateway) as client, pytest.raises(smtplib.SMTPDataError) as error:
        client.sendmail("someone@example.org", [address], EXTERNAL)
    assert error.value.smtp_code == 451
    with factory() as session:
        assert session.scalar(select(func.count()).select_from(Message)) == 0


# --- reply parsing and header handling ----------------------------------------------------


def test_reply_parsing() -> None:
    reply = {
        "action": "add header",
        "score": 7.2,
        "milter": {
            "add_headers": {"Authentication-Results": {"value": AUTH_RESULTS.decode()}},
            "remove_headers": {"X-Spam": 0, "Authentication-Results": 0, "bad name:": 1},
        },
    }
    result = parse_reply(reply)
    assert result.spam and result.authentication_results == AUTH_RESULTS
    assert result.remove_headers == {"x-spam", "authentication-results"}
    for value in ("a;\nspf=pass", "a;\r\nspf=pass", "café;", "a;\r\n\tb\r\nX-Injected: 1"):
        assert (
            parse_reply(
                reply | {"milter": {"add_headers": {"Authentication-Results": value}}}
            ).authentication_results
            is None
        )
    for broken in ({"action": "explode", "score": 1}, {"score": 1}, {"action": "reject"}):
        with pytest.raises(ScannerUnavailableError):
            parse_reply(broken)


def test_strip_header_fields() -> None:
    message = (
        b"Subject: hi\r\nX-Spam: Yes\r\n  folded continuation\r\nFrom: a@b\r\n"
        b"\r\nX-Spam: in the body stays\r\n"
    )
    assert strip_header_fields(message, frozenset({"x-spam"})) == (
        b"Subject: hi\r\nFrom: a@b\r\n\r\nX-Spam: in the body stays\r\n"
    )
    names = frozenset({"x-spam"})
    # Found by fuzzing: a malformed line does not end the header block (a lenient reader
    # would still take the next line for a header), so the forged field is removed.
    assert strip_header_fields(b"\x00\r\nX-Spam: Yes\r\n\r\nbody", names) == b"\x00\r\n\r\nbody"
    # Obsolete syntax: whitespace before the colon is still the field.
    assert strip_header_fields(b"X-Spam : Yes\r\nTo: x\r\n", names) == b"To: x\r\n"
    # A lone CR does not split a line (only LF does).
    assert strip_header_fields(b"To: a\rX-Spam: Yes\r\n", names) == b"To: a\rX-Spam: Yes\r\n"
    assert strip_header_fields(b"X-Spam: Yes\nTo: x\n", names) == b"To: x\n"


# --- the Rspamd HTTP client ---------------------------------------------------------------


class FakeRspamd(BaseHTTPRequestHandler):
    reply: Any = {"action": "no action", "score": 0.5}
    status = 200
    seen: list[tuple[str, list[tuple[str, str]], bytes]] = []

    def do_POST(self) -> None:  # noqa: N802
        body = self.rfile.read(int(self.headers["Content-Length"]))
        FakeRspamd.seen.append((self.path, list(self.headers.items()), body))
        payload = (
            json.dumps(self.reply).encode() if not isinstance(self.reply, bytes) else self.reply
        )
        self.send_response(self.status)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args: Any) -> None:
        pass


@pytest.fixture
def rspamd() -> Iterator[str]:
    FakeRspamd.reply, FakeRspamd.status, FakeRspamd.seen = (
        {"action": "no action", "score": 0.5},
        200,
        [],
    )
    server = HTTPServer(("127.0.0.1", 0), FakeRspamd)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def scan_request() -> ScanRequest:
    return ScanRequest(
        content=EXTERNAL,
        peer="192.0.2.1",
        helo="mx.example.org",
        mail_from="someone@example.org",
        recipients=["a@mail.test", "b@mail.test"],
        hostname="mx.agnus.test",
    )


def test_rspamd_client_protocol(rspamd: str) -> None:
    result = RspamdScanner(rspamd, 5).scan(scan_request())
    assert result.action is Action.ACCEPT and result.score == 0.5
    [(path, headers, body)] = FakeRspamd.seen
    assert path == "/checkv2" and body == EXTERNAL
    assert [v for k, v in headers if k == "Rcpt"] == ["a@mail.test", "b@mail.test"]
    assert ("IP", "192.0.2.1") in headers and ("MTA-Name", "mx.agnus.test") in headers
    assert ("From", "someone@example.org") in headers and ("Helo", "mx.example.org") in headers


@pytest.mark.parametrize(
    ("status", "reply"), [(500, {"error": "x"}), (200, b"not json"), (200, [1, 2])]
)
def test_rspamd_client_failures(rspamd: str, status: int, reply: Any) -> None:
    FakeRspamd.status, FakeRspamd.reply = status, reply
    with pytest.raises(ScannerUnavailableError):
        RspamdScanner(rspamd, 5).scan(scan_request())


def test_rspamd_client_unreachable_and_bad_urls() -> None:
    with pytest.raises(ScannerUnavailableError):
        RspamdScanner("http://127.0.0.1:1", 2).scan(scan_request())
    for url in ("https://rspamd:11333", "rspamd:11333", "http://"):
        with pytest.raises(ValueError):
            RspamdScanner(url, 5)


def test_without_checks_the_result_is_none(
    app: Any,  # noqa: F811
    gateway: Gateway,
    scanner: FakeScanner,
) -> None:
    scanner.result = ScanResult(Action.ACCEPT, 0.0, None, frozenset())
    alice, _ = deliver_one(app, gateway, FORGED + EXTERNAL)
    plaintext = open_external(alice, alice.keys, inbox(alice)[0]["id"])
    domain = gateway.settings.mail_domain.encode()
    assert b"\r\nAuthentication-Results: " + domain + b"; none\r\nX-Spam: No\r\n" in plaintext
    assert plaintext.count(b"Authentication-Results:") == 1
