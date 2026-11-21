"""A test MTA (the recipient's server) and a fake DNS for the outbound service tests.

Replies are chosen by the recipient's local part: ``reject*`` → 550 5.1.1, ``later*`` →
451 4.2.0; anything else is accepted. ``data_reply`` overrides the reply to DATA.
"""

import ssl
from dataclasses import dataclass, field
from typing import Any

from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP, Envelope, Session

from tests.unit.test_inbound import free_port


@dataclass
class Received:
    mail_from: str
    recipients: list[str]
    content: bytes
    tls: bool


@dataclass
class RecordingHandler:
    received: list[Received] = field(default_factory=list)
    data_reply: str = "250 2.0.0 OK queued"

    async def handle_RCPT(  # noqa: N802  (aiosmtpd hook name)
        self, _server: SMTP, _session: Session, envelope: Envelope, address: str, _options: Any
    ) -> str:
        local = address.partition("@")[0].lower()
        if local.startswith("reject"):
            return "550 5.1.1 no such user"
        if local.startswith("later"):
            return "451 4.2.0 try again later"
        envelope.rcpt_tos.append(address)
        return "250 2.1.5 OK"

    async def handle_DATA(  # noqa: N802  (aiosmtpd hook name)
        self, _server: SMTP, session: Session, envelope: Envelope
    ) -> str:
        if self.data_reply.startswith("250"):
            content = envelope.original_content or b""
            self.received.append(
                Received(
                    str(envelope.mail_from),
                    list(envelope.rcpt_tos),
                    content,
                    session.ssl is not None,
                )
            )
        return self.data_reply


class TestMta(Controller):
    """Listens on 127.0.0.1; with ``tls`` it offers STARTTLS (never requires it)."""

    __test__ = False  # not a pytest class

    def __init__(self, tls: ssl.SSLContext | None = None) -> None:
        self.recorder = RecordingHandler()
        super().__init__(
            self.recorder,
            hostname="127.0.0.1",
            port=free_port(),
            tls_context=tls,
            require_starttls=False,
        )

    @property
    def relay(self) -> tuple[str, int]:
        return ("127.0.0.1", self.port)


@dataclass
class FakeResolver:
    """``mx``: domain → hosts (missing: implicit MX); ``a``: host → addresses."""

    mx: dict[str, list[str]] = field(default_factory=dict)
    a: dict[str, list[str]] = field(default_factory=dict)
    errors: dict[str, Exception] = field(default_factory=dict)

    def mail_hosts(self, domain: str) -> list[str]:
        if domain in self.errors:
            raise self.errors[domain]
        return self.mx.get(domain, [domain])

    def addresses(self, host: str) -> list[str]:
        return self.a.get(host, [])
