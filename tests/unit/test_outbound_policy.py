"""What the outbound service accepts to send."""

from datetime import UTC, datetime

import pytest

from agnusmail.modules.outbound.policy import PolicyError, prepare

SENDER = "alice@mail.example.com"
NOW = datetime(2026, 11, 13, 12, 0, tzinfo=UTC)


def run(message: bytes) -> bytes:
    return prepare(
        message, sender=SENDER, message_id="ab" * 16, mail_domain="mail.example.com", now=NOW
    )


def header_of(prepared: bytes) -> list[bytes]:
    return prepared.split(b"\r\n\r\n", 1)[0].split(b"\r\n")


BASE = (
    b"From: Alice <alice@mail.example.com>\r\nTo: bob@example.org\r\n"
    b"Subject: hi\r\n\r\nbody line\r\n"
)


def test_adds_date_and_message_id_and_keeps_the_body() -> None:
    out = run(BASE)
    header = header_of(out)
    assert header[0] == b"Date: Fri, 13 Nov 2026 12:00:00 +0000"
    assert header[1] == b"Message-ID: <" + b"ab" * 16 + b"@mail.example.com>"
    assert out.endswith(b"\r\n\r\nbody line\r\n")


def test_keeps_the_clients_date_and_message_id() -> None:
    message = b"Date: Thu, 12 Nov 2026 10:00:00 +0000\r\nMessage-ID: <x@y>\r\n" + BASE
    header = header_of(run(message))
    assert header.count(b"Message-ID: <x@y>") == 1
    assert not any(line.startswith(b"Date: Fri") for line in header)


def test_bare_lf_becomes_crlf() -> None:
    out = run(BASE.replace(b"\r\n", b"\n"))
    assert b"\n" not in out.replace(b"\r\n", b"")


def test_strips_bcc_and_server_fields() -> None:
    message = (
        b"Received: from somewhere\r\nBcc: hidden@example.org\r\n"
        b"DKIM-Signature: v=1; forged\r\nAuthentication-Results: x; dkim=pass\r\n"
        b"ARC-Seal: i=1; forged\r\nReturn-Path: <other@example.org>\r\n"
        b"X-Spam: no\r\n" + BASE
    )
    out = run(message)
    for name in (b"Received", b"Bcc", b"DKIM-Signature", b"Authentication-Results", b"ARC-Seal"):
        assert name not in out
    assert b"hidden@example.org" not in out


def test_folded_bcc_goes_with_its_continuation() -> None:
    message = b"Bcc: first@hidden.example,\r\n second@hidden.example\r\n" + BASE
    assert b"hidden.example" not in run(message)


@pytest.mark.parametrize(
    ("message", "reason"),
    [
        (BASE.replace(b"alice@", b"mallory@"), "from_not_sender"),
        (BASE.replace(b"From: Alice <alice@mail.example.com>\r\n", b""), "from_missing"),
        (
            BASE.replace(b"Alice <alice@mail.example.com>", b"alice@mail.example.com, x@y.org"),
            "from_not_sender",
        ),
        (b"From: alice@mail.example.com\r\n" + BASE, "duplicate_header"),
        (b"Subject: again\r\n" + BASE, "duplicate_header"),
        (b"Sender: mallory@example.org\r\n" + BASE, "sender_not_sender"),
        (BASE.replace(b"body line", "corpo é".encode()), "not_7bit"),
        (BASE.replace(b"body line", b"a\rb"), "bare_cr"),
        (BASE.replace(b"body line", b"x" * 999), "line_too_long"),
        (b"Not a header line\r\n" + BASE, "malformed_header"),
        (b" leading continuation\r\n" + BASE, "malformed_header"),
        (b"From : alice@mail.example.com\r\nTo: b@example.org\r\n\r\nx\r\n", "malformed_header"),
    ],
)
def test_refusals(message: bytes, reason: str) -> None:
    with pytest.raises(PolicyError) as caught:
        run(message)
    assert caught.value.reason == reason


def test_sender_comparison_ignores_case() -> None:
    run(BASE.replace(b"alice@mail.example.com", b"Alice@Mail.Example.com"))


def test_message_without_body() -> None:
    out = run(b"From: alice@mail.example.com\r\nTo: b@example.org\r\n")
    assert out.endswith(b"To: b@example.org\r\n\r\n")
