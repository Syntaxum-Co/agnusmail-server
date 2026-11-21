"""What the outbound service accepts to send, checked after decrypting.

The From address is inside the ciphertext, so the API cannot check it: here the
message must have exactly one From, equal to the sender's address (no sending as
someone else), and nothing a server writes (trace and authentication fields) survives.
Strict on purpose — the client builds the message, so anything ambiguous is refused
instead of repaired:

- 7-bit ASCII only (bodies in quoted-printable/base64; no SMTPUTF8 or 8BITMIME);
- lines of at most 998 octets (RFC 5322 §2.1.1); LF alone becomes CRLF, CR alone is
  refused;
- a well-formed header block, with the RFC 5322 §3.6 single-occurrence fields at most
  once;
- Bcc is removed (the envelope carries those recipients); Message-ID and Date are added
  when missing.
"""

import re
from datetime import datetime
from email.utils import format_datetime, getaddresses

MAX_LINE = 998
FIELD = re.compile(rb"^([!-9;-~]+):")
SINGLE = frozenset(
    {
        "from",
        "sender",
        "reply-to",
        "to",
        "cc",
        "bcc",
        "subject",
        "date",
        "message-id",
        "in-reply-to",
        "references",
    }
)
# Written by servers on the path, never by the author: dropped if the client sent them.
SERVER_FIELDS = frozenset(
    {
        "bcc",
        "received",
        "return-path",
        "delivered-to",
        "dkim-signature",
        "arc-seal",
        "arc-message-signature",
        "arc-authentication-results",
        "authentication-results",
        "x-spam",
        "x-spam-score",
    }
)


class PolicyError(ValueError):
    """The message is refused for every recipient; ``reason`` is a stable code."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _lines(message: bytes) -> list[bytes]:
    if not message.isascii():
        raise PolicyError("not_7bit")
    normalized = re.sub(rb"\r?\n", b"\r\n", message)
    if b"\r" in normalized.replace(b"\r\n", b""):
        raise PolicyError("bare_cr")
    lines = normalized.split(b"\r\n")
    if lines and lines[-1] == b"":
        lines.pop()
    if any(len(line) > MAX_LINE for line in lines):
        raise PolicyError("line_too_long")
    return lines


def _fields(header: list[bytes]) -> list[tuple[str, list[bytes]]]:
    fields: list[tuple[str, list[bytes]]] = []
    for line in header:
        if line[:1] in (b" ", b"\t"):
            if not fields:
                raise PolicyError("malformed_header")
            fields[-1][1].append(line)
            continue
        match = FIELD.match(line)
        if match is None:
            raise PolicyError("malformed_header")
        fields.append((match.group(1).decode("ascii").lower(), [line]))
    return fields


def _value(lines: list[bytes]) -> str:
    joined = b"".join(lines).decode("ascii")
    return joined.partition(":")[2].strip()


def _only_sender(values: list[str], sender: str, reason: str) -> None:
    addresses = getaddresses(values)
    if len(addresses) != 1 or addresses[0][1].lower() != sender.lower():
        raise PolicyError(reason)


def prepare(
    message: bytes, *, sender: str, message_id: str, mail_domain: str, now: datetime
) -> bytes:
    """The message as it will be signed and sent, or ``PolicyError``."""
    lines = _lines(message)
    try:
        split = lines.index(b"")
    except ValueError:
        split = len(lines)
    header, body = lines[:split], lines[split + 1 :]
    fields = _fields(header)
    names = [name for name, _ in fields]
    if any(names.count(name) > 1 for name in SINGLE):
        raise PolicyError("duplicate_header")
    values = {name: _value(raw) for name, raw in fields}
    if "from" not in values:
        raise PolicyError("from_missing")
    _only_sender([values["from"]], sender, "from_not_sender")
    if "sender" in values:
        _only_sender([values["sender"]], sender, "sender_not_sender")

    kept = [raw for name, raw in fields if name not in SERVER_FIELDS]
    added: list[bytes] = []
    if "date" not in values:
        added.append(f"Date: {format_datetime(now)}".encode("ascii"))
    if "message-id" not in values:
        added.append(f"Message-ID: <{message_id}@{mail_domain}>".encode("ascii"))
    out = added + [line for raw in kept for line in raw]
    return b"\r\n".join([*out, b"", *body]) + b"\r\n"
