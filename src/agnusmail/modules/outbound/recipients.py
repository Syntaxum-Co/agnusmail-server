"""External recipient addresses (envelope, RFC 5321) for the outbound channel.

Deliberately narrower than RFC 5322: dot-atom local part (no quoted strings), a DNS
hostname as domain (no address literals), ASCII only (no SMTPUTF8). The domain is
lowercased; the local part is kept as written (it may be case-sensitive remotely).
"""

import re

from agnusmail.modules.outbound.models import MAX_ADDRESS_LENGTH

ATOM = r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+"
LOCAL_PART = re.compile(rf"^{ATOM}(\.{ATOM})*$")
LABEL = r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
DOMAIN = re.compile(rf"^({LABEL}\.)+[a-z]{{2,63}}$")


class InvalidRecipientError(ValueError):
    pass


def normalize_recipient(address: str) -> str:
    local, separator, domain = address.strip().rpartition("@")
    domain = domain.lower()
    if (
        not separator
        or not 1 <= len(local) <= 64
        or not LOCAL_PART.fullmatch(local)
        or len(domain) > 253
        or not DOMAIN.fullmatch(domain)
    ):
        raise InvalidRecipientError("malformed address")
    normalized = f"{local}@{domain}"
    if len(normalized) > MAX_ADDRESS_LENGTH:
        raise InvalidRecipientError("address too long")
    return normalized


def domain_of(address: str) -> str:
    return address.rpartition("@")[2]


def is_internal(address: str, mail_domain: str) -> bool:
    """Our own domain (and its subdomains) is reached through the E2EE channel."""
    domain = domain_of(address)
    return domain == mail_domain or domain.endswith("." + mail_domain)
