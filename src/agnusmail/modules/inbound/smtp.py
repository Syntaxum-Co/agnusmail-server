"""SMTP side of the inbound gateway: an aiosmtpd handler, in memory.

- ``RCPT``: only active addresses of this service. Unknown → ``550``; after
  ``inbound_max_unknown_recipients`` unknown addresses in one connection it is closed
  (resolution already reveals existence, this limits enumeration). An account
  without a device key yet → ``450`` (the sender retries).
- ``DATA``: antispam first (Rspamd): ``reject`` → ``550``; ``soft reject`` and
  ``greylist`` → ``451``; spam to keep → ``X-Spam: Yes`` inside the ciphertext. Then
  ``250`` only after the ciphertext is committed. Any failure, including the
  scanner, is a temporary ``451``: nothing was written, the sending server retries.
- The message is never logged, written to disk, or kept after the reply.

Connections (step 7.4): STARTTLS offered (TLS 1.2+; never required — RFC 3207 §4 for a
public MX), an idle timeout, a hard cap on each connection's lifetime (slow senders reset
the idle timer on every line), per-command call limits, and caps on simultaneous
connections in total and per client IP: over a cap the client gets ``421`` instead of
the greeting. Across connections and gateway processes (Redis, hourly windows per client
IP): unknown recipients (enumeration → ``421`` and close) and messages (→ ``451``). If
Redis fails these two limits let mail through and the failure is logged, like the API's
rate limits; the per-connection caps still apply.

Client IP: the socket peer, or, behind a load balancer, the source address of a PROXY
protocol header — accepted only from ``inbound_trusted_proxies`` (anything else closes the
connection before the greeting). Behind a proxy the per-IP connection cap counts the
proxy; the hourly per-IP limits and Rspamd use the real client IP. Outside the local
environment a non-public client IP is logged once: Rspamd would skip SPF/DKIM/DMARC.
"""

import asyncio
import ipaddress
import logging
import ssl
from collections import Counter
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aiosmtpd.proxy_protocol import V2_CMD, ProxyData
from aiosmtpd.smtp import SMTP, Envelope
from aiosmtpd.smtp import Session as SmtpSession
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.core.config import Settings
from agnusmail.core.logging import get_logger
from agnusmail.infrastructure.metrics import INBOUND
from agnusmail.infrastructure.redis.rate_limit import RateLimiter
from agnusmail.modules.inbound.antispam import (
    Action,
    Scanner,
    ScannerUnavailableError,
    ScanRequest,
)
from agnusmail.modules.inbound.delivery import (
    Arrival,
    GatewayContext,
    MessageTooLargeError,
    RecipientUnavailableError,
    RecipientUnknownError,
    deliver,
    has_device_key,
    header_safe,
    resolve_recipient,
)

log = get_logger(__name__)

# The stored SEIPDv2 body adds about 30 bytes per 4 KiB chunk plus headers; this margin
# also covers the trace headers the gateway prepends.
ENCRYPTION_MARGIN_BYTES = 32 * 1024

OK_RECIPIENT = "250 2.1.5 Recipient OK"
UNKNOWN_RECIPIENT = "550 5.1.1 No such user here"
NO_KEYS_YET = "450 4.2.1 Mailbox temporarily unavailable"
MAILBOX_FULL = "452 4.2.2 Mailbox full"
TOO_MANY_RECIPIENTS = "452 4.5.3 Too many recipients"
TOO_MANY_UNKNOWN = "421 4.7.0 Too many unknown recipients, closing connection"
ACCEPTED = "250 2.0.0 Message accepted"
TOO_LARGE = "552 5.3.4 Message too big"
TEMPORARY_FAILURE = "451 4.3.0 Temporary failure, try again later"
REJECTED_AS_SPAM = "550 5.7.1 Message rejected as spam"
TRY_LATER = "451 4.7.1 Try again later"
TOO_MANY_MESSAGES = "451 4.7.1 Too many messages from your address, try again later"
RATE_WINDOW_SECONDS = 3600
TOO_MANY_CONNECTIONS = b"421 4.7.0 Too many connections, try again later\r\n"
COMMAND_CALL_LIMIT = 100  # per command, per connection


@dataclass(frozen=True)
class Verdict:
    annotations: tuple[bytes, ...]
    strip: frozenset[str]


def data_size_limit(settings: Settings) -> int:
    return max(settings.max_message_bytes - ENCRYPTION_MARGIN_BYTES, 1024)


class InboundHandler:
    def __init__(
        self,
        factory: sessionmaker[Session],
        ctx: GatewayContext,
        settings: Settings,
        scanner: Scanner | None = None,
        rates: RateLimiter | None = None,
    ) -> None:
        self.factory = factory
        self.ctx = ctx
        self.scanner = scanner  # None only in local development
        self.rates = rates  # None: no limits across connections (tests, local)
        self.unknown_per_hour = settings.inbound_unknown_recipients_per_ip_per_hour
        self.messages_per_hour = settings.inbound_messages_per_ip_per_hour
        self.hostname = settings.inbound_smtp_hostname or settings.mail_domain
        self.max_recipients = settings.max_message_recipients
        self.max_unknown = settings.inbound_max_unknown_recipients
        self.connections = ConnectionLimiter(
            settings.inbound_max_connections, settings.inbound_max_connections_per_ip
        )
        self.trusted_proxies = [
            ipaddress.ip_network(cidr, strict=False) for cidr in settings.inbound_trusted_proxies
        ]
        self.warn_non_public = settings.environment != "local"

    # --- client IP ----------------------------------------------------------------------

    async def handle_PROXY(  # noqa: N802 (aiosmtpd hook name)
        self, server: SMTP, session: SmtpSession, envelope: Envelope, proxy_data: ProxyData
    ) -> bool:
        """Accept a PROXY header only from a trusted load balancer."""
        peer = _peer_ip(session.peer)
        try:
            trusted = any(ipaddress.ip_address(peer) in net for net in self.trusted_proxies)
        except ValueError:
            trusted = False
        if not trusted:
            log.warning("inbound_proxy_untrusted")
            return False
        if proxy_data.command == V2_CMD.LOCAL:  # the balancer's own health check
            return True
        return bool(proxy_data.valid and proxy_data.src_addr is not None)

    def _note_non_public(self, ip: str) -> None:
        if not self.warn_non_public:
            return
        try:
            public = ipaddress.ip_address(ip).is_global
        except ValueError:
            public = False
        if not public:
            self.warn_non_public = False  # once per process
            log.warning("inbound_client_ip_not_public", hint="check PROXY protocol / port mapping")

    async def _within(self, kind: str, ip: str, limit: int) -> bool:
        """Count one event for the client IP in the current hour; False over the limit."""
        if self.rates is None:
            return True
        try:
            return await self.rates.check(f"inbound:{kind}:{ip}", limit, RATE_WINDOW_SECONDS)
        except Exception as exc:  # Redis down: let mail through, keep the local caps
            log.error("inbound_rate_limit_unavailable", error=type(exc).__name__)
            return True

    # --- RCPT ---------------------------------------------------------------------------

    def _recipient_status(self, address: str) -> str:
        now = datetime.now(UTC)
        with self.factory() as session:
            user = resolve_recipient(session, address, self.ctx)
            if user is None:
                return UNKNOWN_RECIPIENT
            if not has_device_key(session, user, now):
                return NO_KEYS_YET
            quota = self.ctx.quota
            if quota is not None and not quota.accepts(session, user.id, 0, now):
                return MAILBOX_FULL  # suspended or storage full
            return OK_RECIPIENT

    async def handle_RCPT(  # noqa: N802 (aiosmtpd hook name)
        self,
        server: SMTP,
        session: SmtpSession,
        envelope: Envelope,
        address: str,
        rcpt_options: list[str],
    ) -> str:
        if len(envelope.rcpt_tos) >= self.max_recipients:
            return TOO_MANY_RECIPIENTS
        status = await asyncio.to_thread(self._recipient_status, address)
        if status == UNKNOWN_RECIPIENT:
            unknown = getattr(session, "agnusmail_unknown", 0) + 1
            session.agnusmail_unknown = unknown  # type: ignore[attr-defined]
            within_hour = await self._within("unknown", client_ip(session), self.unknown_per_hour)
            if unknown > self.max_unknown or not within_hour:
                log.info("inbound_connection_closed", reason="unknown_recipients")
                transport = server.transport
                if transport is not None:  # after the reply is written
                    asyncio.get_running_loop().call_soon(transport.close)
                return TOO_MANY_UNKNOWN
        if status == OK_RECIPIENT:
            envelope.rcpt_tos.append(address)
        return status

    # --- DATA ---------------------------------------------------------------------------

    async def _scan(self, arrival: Arrival, recipients: list[str]) -> "Verdict | str":
        if self.scanner is None:
            return Verdict((), frozenset())
        request = ScanRequest(
            content=arrival.content,
            peer=header_safe(arrival.peer, 45),
            helo=header_safe(arrival.helo),
            mail_from=header_safe(arrival.mail_from) if arrival.mail_from else "",
            recipients=[header_safe(r) for r in recipients],
            hostname=self.hostname,
        )
        result = await asyncio.to_thread(self.scanner.scan, request)
        log.info("inbound_scanned", action=result.action.value)
        if result.action is Action.REJECT:
            return REJECTED_AS_SPAM
        if result.action in (Action.SOFT_REJECT, Action.GREYLIST):
            return TRY_LATER
        # Always exactly one Authentication-Results, ours. Rspamd builds none when it ran
        # no checks (e.g. a peer in its local networks): then "none" (RFC 8601 §2.2).
        results = result.authentication_results or f"{self.hostname}; none".encode("ascii")
        fields = [b"Authentication-Results: " + results]
        fields.append(b"X-Spam: " + (b"Yes" if result.spam else b"No"))
        fields.append(f"X-Spam-Score: {result.score:.2f}".encode("ascii"))
        return Verdict(tuple(fields), result.remove_headers)

    def _deliver(self, arrival: Arrival, recipients: list[str]) -> int:
        with self.factory() as session, session.begin():
            return len(deliver(session, recipients, arrival, self.ctx, datetime.now(UTC)))

    async def handle_DATA(  # noqa: N802 (aiosmtpd hook name)
        self, server: SMTP, session: SmtpSession, envelope: Envelope
    ) -> str:
        reply = await self._handle_data(server, session, envelope)
        INBOUND.labels(outcome=reply[:3]).inc()  # the reply code only
        return reply

    async def _handle_data(self, server: SMTP, session: SmtpSession, envelope: Envelope) -> str:
        ip = client_ip(session)
        self._note_non_public(ip)
        if not await self._within("messages", ip, self.messages_per_hour):
            log.info("inbound_message_deferred", reason="rate_limit")
            envelope.content = envelope.original_content = None
            return TOO_MANY_MESSAGES
        content = envelope.content
        assert isinstance(content, bytes)  # decode_data=False
        arrival = Arrival(
            content=content,
            mail_from=envelope.mail_from or "",
            helo=session.host_name or "",
            peer=ip,
            hostname=self.hostname,
            esmtp=bool(session.extended_smtp),
            received_at=datetime.now(UTC),
            tls=session.ssl is not None,
        )
        try:
            verdict = await self._scan(arrival, list(envelope.rcpt_tos))
            if isinstance(verdict, str):
                return verdict  # refused
            arrival = replace(arrival, annotations=verdict.annotations, strip=verdict.strip)
            count = await asyncio.to_thread(self._deliver, arrival, list(envelope.rcpt_tos))
        except ScannerUnavailableError as exc:
            log.error("inbound_scan_failed", error=str(exc))
            return TEMPORARY_FAILURE
        except MessageTooLargeError:
            return TOO_LARGE
        except (RecipientUnknownError, RecipientUnavailableError) as exc:
            # State changed since RCPT: let the sender retry and get the RCPT answer.
            log.info("inbound_delivery_deferred", reason=type(exc).__name__)
            return TEMPORARY_FAILURE
        except Exception as exc:  # never log the exception text: it may quote content
            log.error("inbound_delivery_failed", error=type(exc).__name__)
            return TEMPORARY_FAILURE
        finally:
            envelope.content = envelope.original_content = None
            del arrival, content
        log.info("inbound_delivered", recipients=count)
        return ACCEPTED


def quiet_library_logging() -> None:
    """aiosmtpd logs the client IP, envelope addresses and commands at INFO and every
    DATA line (the message) at DEBUG, on the stdlib logger ``mail.log``. Only its
    warnings and errors may reach the logs."""
    logging.getLogger("mail.log").setLevel(logging.WARNING)


def _peer_ip(peer: Any) -> str:
    return str(peer[0]) if isinstance(peer, tuple) else "unknown"


def client_ip(session: SmtpSession) -> str:
    """The real client IP: from an accepted PROXY header, else the socket peer."""
    data = session.proxy_data
    if data is not None and data.valid and data.src_addr is not None:
        return str(data.src_addr)
    return _peer_ip(session.peer)


class ConnectionLimiter:
    """Simultaneous connections, in total and per client IP (one gateway process)."""

    def __init__(self, total: int, per_ip: int) -> None:
        self.total, self.per_ip = total, per_ip
        self.open: Counter[str] = Counter()

    def acquire(self, ip: str) -> bool:
        if sum(self.open.values()) >= self.total or self.open[ip] >= self.per_ip:
            return False
        self.open[ip] += 1
        return True

    def release(self, ip: str) -> None:
        self.open[ip] -= 1
        if self.open[ip] <= 0:
            del self.open[ip]


class GatewaySMTP(SMTP):
    """aiosmtpd's server plus connection caps and a lifetime limit."""

    def __init__(self, handler: InboundHandler, lifetime_seconds: float, **kwargs: Any) -> None:
        super().__init__(handler, **kwargs)
        self._limiter = handler.connections
        self._lifetime = lifetime_seconds
        self._counted_ip: str | None = None
        self._deadline: asyncio.TimerHandle | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        first = self._original_transport is None  # not the STARTTLS re-entry
        super().connection_made(transport)
        if not first:
            return
        peer = transport.get_extra_info("peername")
        ip = str(peer[0]) if isinstance(peer, tuple) else "unknown"
        if not self._limiter.acquire(ip):
            log.info("inbound_connection_refused", reason="too_many_connections")
            if self._handler_coroutine is not None:
                self._handler_coroutine.cancel()  # before the 220 greeting is sent
            assert isinstance(transport, asyncio.WriteTransport)
            transport.write(TOO_MANY_CONNECTIONS)
            transport.close()
            return
        self._counted_ip = ip
        self._deadline = self.loop.call_later(self._lifetime, self._expire)

    def _expire(self) -> None:
        log.info("inbound_connection_closed", reason="lifetime")
        if self.transport is not None:
            self.transport.close()

    def connection_lost(self, error: Exception | None) -> None:
        if self._deadline is not None:
            self._deadline.cancel()
        if self._counted_ip is not None:
            self._limiter.release(self._counted_ip)
            self._counted_ip = None
        super().connection_lost(error)


def build_tls_context(cert_file: Path, key_file: Path) -> ssl.SSLContext:
    """Server context for STARTTLS: TLS 1.2 or newer, the library's secure defaults."""
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    return context


def build_smtp(
    handler: InboundHandler, settings: Settings, tls_context: ssl.SSLContext | None = None
) -> SMTP:
    quiet_library_logging()
    return GatewaySMTP(
        handler,
        settings.inbound_max_connection_seconds,
        data_size_limit=data_size_limit(settings),
        hostname=handler.hostname,
        ident="Agnusmail ESMTP",
        decode_data=False,
        enable_SMTPUTF8=False,
        tls_context=tls_context,
        require_starttls=False,  # RFC 3207 §4: a public MX must not require it
        timeout=settings.inbound_idle_timeout_seconds,
        command_call_limit=COMMAND_CALL_LIMIT,
        proxy_protocol_timeout=(
            settings.inbound_proxy_timeout_seconds if settings.inbound_proxy_protocol else None
        ),
    )
