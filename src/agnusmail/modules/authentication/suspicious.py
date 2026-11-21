"""Suspicious-session detection.

At login the session stores a hashed client fingerprint:
- ``ua``: SHA-256 of the User-Agent header;
- ``net``: SHA-256 of the client network (IPv4 /24, IPv6 /48).

On each authenticated request:
- a different User-Agent is treated as cookie replay from another client: the session
  is revoked (when ``session_bind_user_agent`` is on);
- a different network is only logged as a security event (mobile clients change IPs
  constantly) and the stored network is updated so the event is not repeated.

Hashes are pseudonyms, not anonymisation (the /24 space is small); they exist only so
raw User-Agents and IPs are not kept in the session store.
"""

import hashlib
import ipaddress
from enum import StrEnum

IPV4_PREFIX = 24
IPV6_PREFIX = 48


class Verdict(StrEnum):
    OK = "ok"
    NETWORK_CHANGED = "network_changed"
    USER_AGENT_CHANGED = "user_agent_changed"


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def network_of(ip: str) -> str:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return ip  # non-IP peers (e.g. test clients, unix sockets)
    prefix = IPV4_PREFIX if address.version == 4 else IPV6_PREFIX
    return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))


def fingerprint(user_agent: str, ip: str) -> dict[str, str]:
    return {"ua": _sha256(user_agent), "net": _sha256(network_of(ip))}


def evaluate(stored: dict[str, str], current: dict[str, str]) -> Verdict:
    """Compare fingerprints. Sessions created without one are never flagged."""
    if stored.get("ua") and stored["ua"] != current["ua"]:
        return Verdict.USER_AGENT_CHANGED
    if stored.get("net") and stored["net"] != current["net"]:
        return Verdict.NETWORK_CHANGED
    return Verdict.OK
