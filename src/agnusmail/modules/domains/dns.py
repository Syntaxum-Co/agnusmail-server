"""TXT lookup for domain verification. Injected in the app so tests do not
touch the network (``app.state.dns_txt``)."""

from collections.abc import Callable

import dns.exception
import dns.resolver

from agnusmail.core.exceptions import AgnusmailError

TxtLookup = Callable[[str], list[str]]


class DnsUnavailableError(AgnusmailError):
    status_code = 503
    message = "DNS lookup failed; try again"
    code = "DNS_UNAVAILABLE"


def lookup_txt(name: str, lifetime: float = 10.0) -> list[str]:
    """Every TXT string at ``name`` (multi-string records joined); [] if none."""
    try:
        answer = dns.resolver.Resolver().resolve(name, "TXT", lifetime=lifetime)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.DNSException as exc:
        raise DnsUnavailableError() from exc
    values: list[str] = []
    for record in answer:
        strings = getattr(record, "strings", ())
        values.append(b"".join(strings).decode("ascii", "replace"))
    return values
