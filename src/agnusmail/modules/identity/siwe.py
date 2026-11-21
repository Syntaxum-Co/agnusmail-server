"""SIWE (EIP-4361) message parsing and signature verification.

The parser follows the EIP-4361 ABNF strictly: fields must appear exactly once, in
the specified order, separated by LF. Anything else is rejected, so the server can
never interpret a signed message differently from the wallet that displayed it.

Limitation: only EOA signatures (EIP-191 personal_sign) are supported; smart
contract wallets (EIP-1271) require an on-chain call and are not supported yet.
"""

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol
from urllib.parse import urlsplit

from eth_account import Account
from eth_account.messages import encode_defunct

MAX_MESSAGE_LENGTH = 4096
HEADER_SUFFIX = " wants you to sign in with your Ethereum account:"
NONCE_REGEX = re.compile(r"^[A-Za-z0-9]{8,}$")
ETHEREUM_ADDRESS_REGEX = re.compile(r"^0x[0-9a-fA-F]{40}$")
CHAIN_ID_REGEX = re.compile(r"^[0-9]{1,20}$")
DOMAIN_REGEX = re.compile(r"^[^\s/]+$")
SCHEME_REGEX = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*$")
SUPPORTED_VERSION = "1"

MANDATORY_FIELDS = ("URI", "Version", "Chain ID", "Nonce", "Issued At")
OPTIONAL_FIELDS = ("Expiration Time", "Not Before", "Request ID")


class SiweError(Exception):
    """Raised for malformed messages and failed checks. Messages are safe to expose."""


class NonceConsumer(Protocol):
    async def consume(self, nonce: str) -> bool: ...


@dataclass(frozen=True)
class SiweMessage:
    domain: str
    address: str
    statement: str | None
    uri: str
    version: str
    chain_id: int
    nonce: str
    issued_at: datetime
    expiration_time: datetime | None
    not_before: datetime | None
    request_id: str | None
    resources: tuple[str, ...]
    scheme: str | None = None


@dataclass(frozen=True)
class SiweResult:
    ok: bool
    address: str = ""
    reason: str = ""


def _parse_timestamp(raw: str, field: str) -> datetime:
    """Parse an RFC 3339 date-time (fractional seconds and offsets allowed)."""
    try:
        if "T" not in raw:
            raise ValueError("missing time component")
        parsed = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise SiweError(f"invalid timestamp in {field}") from exc
    if parsed.tzinfo is None:
        raise SiweError(f"timestamp in {field} must include a timezone")
    return parsed.astimezone(UTC)


def _take_field(lines: list[str], index: int, name: str) -> str:
    prefix = f"{name}: "
    if index >= len(lines) or not lines[index].startswith(prefix):
        raise SiweError(f"malformed SIWE message: expected '{name}'")
    value = lines[index][len(prefix) :]
    if not value or value != value.strip():
        raise SiweError(f"malformed SIWE message: invalid '{name}'")
    return value


def parse_message(message: str) -> SiweMessage:
    if len(message) > MAX_MESSAGE_LENGTH:
        raise SiweError("SIWE message too long")
    if "\r" in message:
        raise SiweError("malformed SIWE message: CR not allowed")
    lines = message.split("\n")
    if len(lines) < 9:
        raise SiweError("malformed SIWE message")

    if not lines[0].endswith(HEADER_SUFFIX):
        raise SiweError("malformed SIWE prefix")
    authority = lines[0][: -len(HEADER_SUFFIX)]
    scheme: str | None = None
    domain = authority
    if "://" in authority:  # ABNF: [ scheme "://" ] domain
        scheme, domain = authority.split("://", 1)
        if not SCHEME_REGEX.match(scheme):
            raise SiweError("malformed SIWE scheme")
    if not DOMAIN_REGEX.match(domain):
        raise SiweError("malformed SIWE domain")

    address = lines[1]
    if not ETHEREUM_ADDRESS_REGEX.match(address):
        raise SiweError("invalid ethereum address")
    if lines[2] != "":
        raise SiweError("malformed SIWE message")

    statement: str | None = None
    index = 3
    if lines[3] != "":
        statement = lines[3]
        if len(lines) < 5 or lines[4] != "":
            raise SiweError("malformed SIWE statement")
        index = 5
    else:
        index = 4

    values: dict[str, str] = {}
    for name in MANDATORY_FIELDS:
        values[name] = _take_field(lines, index, name)
        index += 1
    for name in OPTIONAL_FIELDS:
        if index < len(lines) and lines[index].startswith(f"{name}: "):
            values[name] = _take_field(lines, index, name)
            index += 1

    resources: list[str] = []
    if index < len(lines) and lines[index] == "Resources:":
        index += 1
        while index < len(lines) and lines[index].startswith("- "):
            resources.append(lines[index][2:])
            index += 1
    if index != len(lines):
        raise SiweError("malformed SIWE message: unexpected trailing content")

    if values["Version"] != SUPPORTED_VERSION:
        raise SiweError("unsupported SIWE version")
    if not CHAIN_ID_REGEX.match(values["Chain ID"]):
        raise SiweError("invalid chain id")
    if not NONCE_REGEX.match(values["Nonce"]):
        raise SiweError("invalid nonce")

    expiration = values.get("Expiration Time")
    not_before = values.get("Not Before")
    return SiweMessage(
        domain=domain,
        address=address,
        statement=statement,
        uri=values["URI"],
        version=values["Version"],
        chain_id=int(values["Chain ID"]),
        nonce=values["Nonce"],
        issued_at=_parse_timestamp(values["Issued At"], "Issued At"),
        expiration_time=_parse_timestamp(expiration, "Expiration Time") if expiration else None,
        not_before=_parse_timestamp(not_before, "Not Before") if not_before else None,
        request_id=values.get("Request ID"),
        resources=tuple(resources),
        scheme=scheme,
    )


def verify_signature(message: str, signature: str) -> str:
    """Recover the signer address (EIP-191 personal_sign). Raises SiweError on failure."""
    try:
        return str(Account.recover_message(encode_defunct(text=message), signature=signature))
    except Exception as exc:
        raise SiweError("invalid signature") from exc


def check_temporal_validity(
    parsed: SiweMessage, now: datetime, clock_skew: timedelta = timedelta(seconds=60)
) -> None:
    if parsed.issued_at > now + clock_skew:
        raise SiweError("message issued in the future")
    if parsed.not_before is not None and now + clock_skew < parsed.not_before:
        raise SiweError("message not yet valid")
    if parsed.expiration_time is not None and now >= parsed.expiration_time:
        raise SiweError("message expired")


async def siwe_verify(
    message: str,
    signature: str,
    nonce_store: NonceConsumer,
    expected_domain: str = "",
    expected_uri: str = "",
    expected_chain_id: int = 0,
    clock_skew_seconds: int = 60,
) -> SiweResult:
    """Full SIWE check. The nonce is consumed last (atomically), after every other check."""
    try:
        parsed = parse_message(message)
        if expected_domain and parsed.domain != expected_domain:
            raise SiweError("domain mismatch")
        if expected_uri and parsed.uri != expected_uri:
            raise SiweError("uri mismatch")
        # Omitted scheme defaults to https (EIP-4361); when present it must match the URI's.
        if expected_uri and parsed.scheme is not None:
            if parsed.scheme.lower() != urlsplit(expected_uri).scheme.lower():
                raise SiweError("scheme mismatch")
        if expected_chain_id and parsed.chain_id != expected_chain_id:
            raise SiweError("chain id mismatch")
        check_temporal_validity(parsed, datetime.now(UTC), timedelta(seconds=clock_skew_seconds))
        address = verify_signature(message, signature)
        if address.lower() != parsed.address.lower():
            raise SiweError("signature does not match address")
    except SiweError as exc:
        return SiweResult(ok=False, reason=str(exc))
    if not await nonce_store.consume(parsed.nonce):
        return SiweResult(ok=False, reason="nonce unknown or already used")
    return SiweResult(ok=True, address=address)
