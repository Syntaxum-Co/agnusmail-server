"""SMTP delivery to the recipient's server (RFC 5321, RFC 7505).

One transaction per recipient domain, to the MX hosts in preference order (without MX,
the domain itself — RFC 5321 §5.1; a null MX means the domain accepts no mail). STARTTLS
whenever offered (TLS 1.2+, opportunistic: certificates are not verified, as between
most MTAs; MTA-STS/DANE are not implemented yet); ``require_tls`` refuses servers without it.

Only public addresses are contacted: an MX that resolves to a private, loopback or
link-local address is refused, so a user cannot point the service at the internal
network. Results keep the reply code and the enhanced status code, never the text.
"""

import ipaddress
import re
import smtplib
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

import dns.exception
import dns.resolver

from agnusmail.core.logging import get_logger

log = get_logger(__name__)

ENHANCED = re.compile(r"^([245]\.\d{1,3}\.\d{1,3})\b")


class Outcome(StrEnum):
    DELIVERED = "delivered"
    FAILED = "failed"  # permanent
    RETRY = "retry"  # temporary


@dataclass(frozen=True)
class Result:
    outcome: Outcome
    code: int | None = None
    status: str | None = None  # enhanced status code, or a stable local reason


class PermanentDnsError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class TemporaryDnsError(Exception):
    pass


class Resolver(Protocol):
    def mail_hosts(self, domain: str) -> list[str]: ...

    def addresses(self, host: str) -> list[str]: ...


class DnsResolver:
    """MX and A/AAAA through dnspython (the system's configured resolvers)."""

    def __init__(self, lifetime: float = 20.0) -> None:
        self._resolver = dns.resolver.Resolver()
        self._lifetime = lifetime

    def _query(self, name: str, rdtype: str) -> list[object]:
        try:
            return list(self._resolver.resolve(name, rdtype, lifetime=self._lifetime))
        except dns.resolver.NXDOMAIN as exc:
            raise PermanentDnsError("nxdomain") from exc
        except dns.resolver.NoAnswer:
            return []
        except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
            raise TemporaryDnsError() from exc
        except dns.exception.DNSException as exc:
            raise TemporaryDnsError() from exc

    def mail_hosts(self, domain: str) -> list[str]:
        records = self._query(domain, "MX")
        if not records:
            return [domain]  # implicit MX (RFC 5321 §5.1)
        ordered = sorted(records, key=lambda r: int(getattr(r, "preference", 0)))
        hosts = [str(getattr(r, "exchange", "")).rstrip(".").lower() for r in ordered]
        if hosts == [""]:
            raise PermanentDnsError("null_mx")  # RFC 7505
        return [host for host in hosts if host]

    def addresses(self, host: str) -> list[str]:
        found: list[str] = []
        for rdtype in ("AAAA", "A"):
            try:
                found += [str(getattr(r, "address", r)) for r in self._query(host, rdtype)]
            except PermanentDnsError:
                return []
        return found


def is_public(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).is_global
    except ValueError:
        return False


def _status(message: bytes | str) -> str | None:
    text = message.decode("ascii", "replace") if isinstance(message, bytes) else message
    match = ENHANCED.match(text.strip())
    return match.group(1) if match else None


def _from_reply(code: int, message: bytes | str) -> Result:
    if 200 <= code < 300:
        return Result(Outcome.DELIVERED, code, _status(message))
    if 500 <= code < 600:
        return Result(Outcome.FAILED, code, _status(message))
    return Result(Outcome.RETRY, code if 400 <= code < 600 else None, _status(message))


def _tls_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # opportunistic (see module docstring)
    return context


class SmtpDelivery:
    def __init__(
        self,
        *,
        hostname: str,
        resolver: Resolver,
        port: int = 25,
        require_tls: bool = False,
        connect_timeout: float = 30.0,
        relay: tuple[str, int] | None = None,
        connect: Callable[..., smtplib.SMTP] = smtplib.SMTP,
    ) -> None:
        self._hostname = hostname
        self._resolver = resolver
        self._port = port
        self._require_tls = require_tls
        self._timeout = connect_timeout
        self._relay = relay
        self._connect = connect

    def _targets(self, domain: str) -> list[tuple[str, int]]:
        """(IP, port) to try, in order. Raises the DNS errors."""
        if self._relay is not None:  # local development and tests (never production)
            return [self._relay]
        targets: list[tuple[str, int]] = []
        for host in self._resolver.mail_hosts(domain):
            addresses = self._resolver.addresses(host)
            public = [a for a in addresses if is_public(a)]
            if addresses and not public:
                log.warning("outbound_mx_not_public", domain=domain)
            targets += [(address, self._port) for address in public]
        return targets

    def deliver(
        self, domain: str, sender: str, recipients: list[str], data: bytes
    ) -> dict[str, Result]:
        try:
            targets = self._targets(domain)
        except PermanentDnsError as exc:
            return dict.fromkeys(recipients, Result(Outcome.FAILED, None, f"dns_{exc.reason}"))
        except TemporaryDnsError:
            return dict.fromkeys(recipients, Result(Outcome.RETRY, None, "dns_temporary"))
        if not targets:
            return dict.fromkeys(recipients, Result(Outcome.FAILED, None, "no_public_address"))
        last = Result(Outcome.RETRY, None, "connection_failed")
        for host, port in targets:
            try:
                results = self._transaction(host, port, sender, recipients, data)
            except _TryNextHostError as exc:
                last = exc.result
                continue
            except (OSError, smtplib.SMTPException):
                last = Result(Outcome.RETRY, None, "connection_failed")
                continue
            return results
        return dict.fromkeys(recipients, last)

    def _transaction(
        self, host: str, port: int, sender: str, recipients: list[str], data: bytes
    ) -> dict[str, Result]:
        with self._connect(
            host, port, local_hostname=self._hostname, timeout=self._timeout
        ) as smtp:
            code, message = smtp.ehlo()
            if not 200 <= code < 300:
                raise _TryNextHostError(Result(Outcome.RETRY, code, "ehlo_refused"))
            if smtp.has_extn("starttls"):
                code, message = smtp.starttls(context=_tls_context())
                if code != 220:
                    raise _TryNextHostError(Result(Outcome.RETRY, code, "starttls_failed"))
                smtp.ehlo()
            elif self._require_tls:
                raise _TryNextHostError(Result(Outcome.RETRY, None, "tls_unavailable"))

            code, message = smtp.mail(sender)
            started = _from_reply(code, message)
            if started.outcome is not Outcome.DELIVERED:
                return dict.fromkeys(recipients, started)
            results: dict[str, Result] = {}
            accepted: list[str] = []
            for address in recipients:
                code, message = smtp.rcpt(address)
                reply = _from_reply(code, message)
                if reply.outcome is Outcome.DELIVERED:
                    accepted.append(address)
                else:
                    results[address] = reply
            if not accepted:
                smtp.rset()
                return results
            try:
                code, message = smtp.data(data)
                final = _from_reply(code, message)
            except smtplib.SMTPDataError as exc:  # refused the DATA command itself
                final = _from_reply(exc.smtp_code, exc.smtp_error)
            for address in accepted:
                results[address] = final
            return results


class _TryNextHostError(Exception):
    def __init__(self, result: Result) -> None:
        super().__init__(result.status)
        self.result = result
