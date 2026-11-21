"""Antispam before encryption: Rspamd over its HTTP protocol.

The gateway sends the message it holds in memory to Rspamd (``POST /checkv2``) with the
envelope as request headers, and gets back an action and the ``Authentication-Results``
header (RFC 8601) that Rspamd builds from its SPF/DKIM/DMARC checks, with the gateway's
name as authserv-id (``MTA-Name``). Rspamd is configured to keep nothing and to send
nothing derived from the content to third parties (``docker/rspamd/README.md``).

Rspamd unavailable or answering something unexpected → the gateway answers a temporary
error (fail closed): the sending server keeps the message and retries.
"""

import http.client
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol
from urllib.parse import urlsplit

MAX_REPLY_BYTES = 1024 * 1024
# A header value Rspamd may hand us: printable ASCII, folded with CRLF + whitespace.
FOLDED_VALUE = re.compile(rb"^[\x20-\x7e]+(\r\n[ \t][\x20-\x7e]+)*$")
HEADER_NAME = re.compile(r"^[!-9;-~]+$")  # RFC 5322 field name


class Action(StrEnum):
    ACCEPT = "no action"
    GREYLIST = "greylist"
    ADD_HEADER = "add header"
    REWRITE_SUBJECT = "rewrite subject"
    SOFT_REJECT = "soft reject"
    REJECT = "reject"


class ScannerUnavailableError(Exception):
    pass


@dataclass(frozen=True)
class ScanRequest:
    content: bytes
    peer: str
    helo: str
    mail_from: str
    recipients: list[str]
    hostname: str  # authserv-id


@dataclass(frozen=True)
class ScanResult:
    action: Action
    score: float
    authentication_results: bytes | None  # header value, already folded
    remove_headers: frozenset[str]  # lowercase field names Rspamd asks to drop

    @property
    def spam(self) -> bool:
        return self.action in (Action.ADD_HEADER, Action.REWRITE_SUBJECT)


class Scanner(Protocol):
    def scan(self, request: ScanRequest) -> ScanResult: ...


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _header_value(value: Any) -> bytes | None:
    if isinstance(value, dict):
        value = value.get("value")
    if not isinstance(value, str):
        return None
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError:
        return None
    return encoded if FOLDED_VALUE.match(encoded) else None


def parse_reply(reply: dict[str, Any]) -> ScanResult:
    try:
        action = Action(reply["action"])
        score = float(reply["score"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ScannerUnavailableError("unexpected scan reply") from exc
    milter = _mapping(reply.get("milter"))
    added = _mapping(milter.get("add_headers"))
    removed = _mapping(milter.get("remove_headers"))
    return ScanResult(
        action=action,
        score=score,
        authentication_results=_header_value(added.get("Authentication-Results")),
        remove_headers=frozenset(
            name.lower() for name in removed if isinstance(name, str) and HEADER_NAME.match(name)
        ),
    )


class RspamdScanner:
    def __init__(self, url: str, timeout_seconds: float) -> None:
        parts = urlsplit(url)
        if parts.scheme != "http" or not parts.hostname:
            raise ValueError("rspamd url must be http://host[:port] (internal network)")
        self.host = parts.hostname
        self.port = parts.port or 11333
        self.timeout = timeout_seconds

    def scan(self, request: ScanRequest) -> ScanResult:
        connection = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        try:
            connection.putrequest("POST", "/checkv2", skip_accept_encoding=True)
            connection.putheader("IP", request.peer)
            connection.putheader("Helo", request.helo)
            connection.putheader("From", request.mail_from)
            for recipient in request.recipients:  # one header per recipient
                connection.putheader("Rcpt", recipient)
            connection.putheader("MTA-Name", request.hostname)
            connection.putheader("Content-Length", str(len(request.content)))
            connection.endheaders(request.content)
            response = connection.getresponse()
            body = response.read(MAX_REPLY_BYTES + 1)
            if response.status != 200 or len(body) > MAX_REPLY_BYTES:
                raise ScannerUnavailableError(f"scan failed with status {response.status}")
            reply = json.loads(body)
        except (OSError, http.client.HTTPException, ValueError) as exc:
            raise ScannerUnavailableError(type(exc).__name__) from exc
        finally:
            connection.close()
        if not isinstance(reply, dict):
            raise ScannerUnavailableError("unexpected scan reply")
        return parse_reply(reply)


LINE = re.compile(rb"[^\n]*\n|[^\n]+\Z")  # LF-terminated lines; a lone CR is not a break


def strip_header_fields(content: bytes, names: frozenset[str]) -> bytes:
    """Drop every field named in ``names`` (lowercase) from the message's header block.

    Read the way the most lenient mail reader might, so that nothing named survives
    anywhere a reader could take it for a header:

    - the header block ends only at the first empty line (or the end): malformed lines
      inside it are kept, but do not end it;
    - a field name may be followed by whitespace before the colon (RFC 5322 obsolete
      syntax);
    - folded fields go with their continuation lines (leading space or tab).

    The body (after the first empty line) is never touched.
    """
    if not names:
        return content
    lines = LINE.findall(content)
    kept: list[bytes] = []
    dropping = False
    for index, line in enumerate(lines):
        bare = line.rstrip(b"\r\n")
        if bare == b"":
            return b"".join(kept) + b"".join(lines[index:])
        if line[:1] in (b" ", b"\t"):
            if not dropping:
                kept.append(line)
            continue
        name, colon, _ = bare.partition(b":")
        field = name.rstrip(b" \t").decode("ascii", "replace").lower()
        dropping = bool(colon) and field in names
        if not dropping:
            kept.append(line)
    return b"".join(kept)
