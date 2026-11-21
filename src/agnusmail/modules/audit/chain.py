"""Per-user hash chain of audit events.

Each event commits to the previous event of the same user::

    event_hash = SHA-256(DOMAIN || canonical_json(payload))

where ``payload`` holds the format version, the owner, the per-user sequence number, the
previous event hash and every stored field of the event. The first event of a chain uses
``GENESIS_HASH`` (32 zero bytes) as its previous hash.

The chain uses no secret: anyone holding the events (the owner, through the API) can
recompute it. It makes rewriting history detectable by whoever remembers a later head
hash (the user's client, an operator checkpoint). It does NOT stop an attacker with write
access to the database from rebuilding a whole consistent chain; that is the accepted
limit of an unanchored chain.

The exact encoding is specified in ``docs/specs/audit-chain-v1.md``. Any change to this
module that alters a hash is a new format version, never an edit of version 1.
"""

import hashlib
import json
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

CHAIN_VERSION = 1
DOMAIN = b"agnusmail/audit-event/v1\n"
HASH_SIZE = 32
GENESIS_HASH = bytes(HASH_SIZE)


class NonCanonicalDetailsError(ValueError):
    """Details contain a value whose JSON form is not stable through storage."""


def _check_canonical(value: Any, path: str = "details") -> None:
    """Allow only values that survive JSON/JSONB storage byte-for-byte.

    Floats are rejected (their textual form may change), and so are non-string keys.
    """
    if value is None or isinstance(value, (bool, str)):
        return
    if isinstance(value, int):
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise NonCanonicalDetailsError(f"{path}: non-string key")
            _check_canonical(item, f"{path}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _check_canonical(item, f"{path}[{index}]")
        return
    raise NonCanonicalDetailsError(f"{path}: unsupported type {type(value).__name__}")


def check_details(details: Mapping[str, Any]) -> None:
    _check_canonical(details)


def format_timestamp(value: datetime) -> str:
    """UTC, always six fractional digits, ``Z`` suffix (naive values are UTC)."""
    utc = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _uuid(value: uuid.UUID | None) -> str | None:
    return None if value is None else str(value)


@dataclass(frozen=True)
class ChainedFields:
    """Everything an event hash commits to."""

    user_id: uuid.UUID
    chain_seq: int
    prev_hash: bytes
    event_type: str
    actor_user_id: uuid.UUID | None
    device_id: uuid.UUID | None
    public_key_id: uuid.UUID | None
    details: Mapping[str, Any]
    created_at: datetime


def canonical_bytes(fields: ChainedFields) -> bytes:
    check_details(fields.details)
    if len(fields.prev_hash) != HASH_SIZE:
        raise ValueError("prev_hash must be 32 bytes")
    payload = {
        "v": CHAIN_VERSION,
        "user_id": str(fields.user_id),
        "seq": fields.chain_seq,
        "prev_hash": fields.prev_hash.hex(),
        "event_type": fields.event_type,
        "actor_user_id": _uuid(fields.actor_user_id),
        "device_id": _uuid(fields.device_id),
        "public_key_id": _uuid(fields.public_key_id),
        "details": fields.details,
        "created_at": format_timestamp(fields.created_at),
    }
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def compute_event_hash(fields: ChainedFields) -> bytes:
    return hashlib.sha256(DOMAIN + canonical_bytes(fields)).digest()


@dataclass(frozen=True)
class ChainCheck:
    """Result of verifying a contiguous run of events."""

    ok: bool
    checked: int
    last_seq: int
    last_hash: bytes
    failed_seq: int | None = None
    reason: str | None = None


def verify_run(
    events: Iterable[tuple[ChainedFields, bytes]], *, start_seq: int, start_hash: bytes
) -> ChainCheck:
    """Verify events (ordered by ``chain_seq``) continuing from a known point.

    ``start_seq``/``start_hash`` are the sequence and hash just before the first event
    (``0``/``GENESIS_HASH`` for a full chain, or a purge checkpoint).
    """
    expected_seq, expected_prev = start_seq + 1, start_hash
    checked = 0
    for fields, stored_hash in events:
        if fields.chain_seq != expected_seq:
            return ChainCheck(
                False, checked, expected_seq - 1, expected_prev, fields.chain_seq, "gap"
            )
        if fields.prev_hash != expected_prev:
            return ChainCheck(
                False, checked, expected_seq - 1, expected_prev, fields.chain_seq, "prev_hash"
            )
        if compute_event_hash(fields) != stored_hash:
            return ChainCheck(
                False, checked, expected_seq - 1, expected_prev, fields.chain_seq, "event_hash"
            )
        checked += 1
        expected_seq, expected_prev = fields.chain_seq + 1, stored_hash
    return ChainCheck(True, checked, expected_seq - 1, expected_prev)
