"""Fuzzing of everything the inbound gateway parses, with Hypothesis.

Each parser gets arbitrary input and may only succeed or fail with its own, expected
error — never crash, hang, or let input escape into the headers it writes. The SMTP
server itself gets arbitrary command lines and must keep answering.
"""

import re
import socket
import string
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from agnusmail.infrastructure.openpgp import (
    EnvelopeRejectedError,
    GatewayKey,
    check_recovery_backup,
    check_seipd_v2,
    generate_gateway_key,
    load_gateway_key,
    pkesk_recipient,
    split_packets,
)
from agnusmail.modules.inbound.antispam import (
    FOLDED_VALUE,
    ScannerUnavailableError,
    ScanResult,
    parse_reply,
    strip_header_fields,
)
from agnusmail.modules.inbound.delivery import Arrival, GatewayContext, header_safe
from agnusmail.modules.inbound.smtp import InboundHandler
from agnusmail.testing.fakes import make_session_factory, make_settings
from tests.unit.test_inbound import DOMAIN, Gateway

FIELD_NAMES = st.sampled_from(["x-spam", "authentication-results", "subject", "x-other"])
HEADER_LINE = st.one_of(
    st.builds(
        lambda name, value: f"{name}: {value}".encode(),
        st.sampled_from(["X-Spam", "Authentication-Results", "Subject", "From", "X-Other"]),
        st.text(alphabet=string.printable.strip("\r\n\x0b\x0c"), max_size=40),
    ),
    st.builds(lambda value: b"\t" + value, st.binary(max_size=30).filter(lambda b: b"\n" not in b)),
    st.binary(max_size=40).filter(lambda b: b"\n" not in b and b"\r" not in b),
)


@given(st.binary(max_size=2048))
def test_packet_parsers_only_reject(data: bytes) -> None:
    for parser in (split_packets, pkesk_recipient, check_seipd_v2, check_recovery_backup):
        try:
            result: Any = parser(data)
        except EnvelopeRejectedError:
            continue
        if parser is split_packets:
            assert b"".join(result) == data  # framing loses and invents nothing


@given(
    st.lists(HEADER_LINE, max_size=12),
    st.binary(max_size=200),
    st.frozensets(FIELD_NAMES),
    st.sampled_from([b"\r\n", b"\n"]),
)
def test_strip_header_fields_touches_only_named_fields(
    headers: list[bytes], body: bytes, names: frozenset[str], eol: bytes
) -> None:
    message = b"".join(line + eol for line in headers) + eol + body
    stripped = strip_header_fields(message, names)
    assert strip_header_fields(stripped, names) == stripped  # idempotent
    assert stripped.endswith(eol + body) or stripped.endswith(body)  # body never touched
    # The header block: lines from the start up to the first empty one (RFC 5322).
    for raw in stripped.split(b"\n"):
        line = raw.removesuffix(b"\r")
        if line == b"":
            break
        name, colon, _ = line.partition(b":")
        field = name.rstrip(b" \t").decode("ascii", "replace").lower()
        if colon and line[:1] not in (b" ", b"\t") and field in names:
            raise AssertionError(line)  # a named field survived in the header block


JSON = st.recursive(
    st.none() | st.booleans() | st.floats(allow_nan=False) | st.integers() | st.text(),
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=20), children, max_size=4)
    ),
    max_leaves=6,
)
REPLY = st.fixed_dictionaries(
    {},
    optional={
        "action": st.sampled_from(["no action", "reject", "add header", "x"]) | JSON,
        "score": st.floats(allow_nan=False) | JSON,
        "milter": st.fixed_dictionaries(
            {},
            optional={
                "add_headers": st.dictionaries(st.text(max_size=30), JSON, max_size=3)
                | st.fixed_dictionaries({"Authentication-Results": st.text() | JSON}),
                "remove_headers": st.dictionaries(st.text(max_size=30), JSON, max_size=3),
            },
        )
        | JSON,
    },
)


@settings(suppress_health_check=[HealthCheck.too_slow])
@given(REPLY)
def test_scan_replies_parse_or_fail_cleanly(reply: dict[str, Any]) -> None:
    try:
        result = parse_reply(reply)
    except ScannerUnavailableError:
        return
    assert isinstance(result, ScanResult)
    if result.authentication_results is not None:
        assert FOLDED_VALUE.match(result.authentication_results)
    for name in result.remove_headers:
        assert re.fullmatch(r"[!-9;-~]+", name) and name == name.lower()


@given(st.text(), st.integers(min_value=1, max_value=300))
def test_header_safe_output_is_printable_and_bounded(value: str, limit: int) -> None:
    safe = header_safe(value, limit)
    assert 0 < len(safe) <= max(limit, len("unknown"))
    assert all(32 < ord(ch) < 127 for ch in safe)


@given(st.text(), st.text(), st.text(), st.text())
def test_trace_headers_cannot_be_forged(mail_from: str, helo: str, peer: str, rcpt: str) -> None:
    arrival = Arrival(
        content=b"Subject: x\r\n\r\nbody",
        mail_from=mail_from,
        helo=helo,
        peer=peer,
        hostname=DOMAIN,
        esmtp=True,
        received_at=datetime(2026, 11, 13, tzinfo=UTC),
    )
    lines = arrival.for_recipient(rcpt).split(b"\r\n")
    assert lines[0].startswith(b"Return-Path: <") and lines[1].startswith(b"Received: from ")
    assert lines[2].startswith(b"\tby ") and lines[3].startswith(b"\tfor <")
    assert lines[4] == b"Subject: x"  # nothing injected between trace and message


# --- the SMTP server with arbitrary command lines ------------------------------------------


@pytest.fixture(scope="module")
def gateway() -> Iterator[Gateway]:
    smtp_settings = make_settings(mail_domain=DOMAIN, inbound_max_connections_per_ip=1000)
    key: GatewayKey = load_gateway_key(generate_gateway_key(), now=datetime.now(UTC))
    handler = InboundHandler(
        make_session_factory(), GatewayContext.from_settings(smtp_settings, key), smtp_settings
    )
    controller = Gateway(handler, smtp_settings)
    controller.start()
    yield controller
    controller.stop()


def read_reply(sock: socket.socket) -> bytes:
    data = b""
    while not re.search(rb"(^|\r\n)\d{3} [^\r\n]*\r\n$", data):
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


COMMAND = st.one_of(
    st.binary(max_size=300).map(lambda b: b.replace(b"\r", b"").replace(b"\n", b"")),
    st.builds(
        lambda verb, arg: verb + b" " + arg,
        st.sampled_from([b"EHLO", b"HELO", b"MAIL FROM:", b"RCPT TO:", b"VRFY", b"AUTH", b"BDAT"]),
        st.binary(max_size=200).map(lambda b: b.replace(b"\r", b"").replace(b"\n", b"")),
    ),
)


@settings(
    max_examples=60, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
@given(st.lists(COMMAND, min_size=1, max_size=8))
def test_smtp_server_survives_arbitrary_commands(gateway: Gateway, commands: list[bytes]) -> None:
    with socket.create_connection((gateway.hostname, gateway.port), timeout=10) as sock:
        assert read_reply(sock).startswith(b"220")
        for command in commands:
            try:
                sock.sendall(command + b"\r\n")
                reply = read_reply(sock)
            except OSError:
                break  # the server may close on abuse; that is fine
            if not reply:
                break
            assert re.match(rb"^[2-5]\d\d[ -]", reply), reply
    # And it keeps serving everyone else.
    with socket.create_connection((gateway.hostname, gateway.port), timeout=10) as sock:
        assert read_reply(sock).startswith(b"220")
        sock.sendall(b"NOOP\r\n")
        assert read_reply(sock).startswith(b"250")
