"""Audit trail API schemas.

Hashes are lowercase hex. With the owner's user id, every field needed to recompute an
event hash is present (``docs/specs/audit-chain-v1.md``).
"""

import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict

from agnusmail.core.schemas import UtcDatetime
from agnusmail.modules.audit.chain import CHAIN_VERSION, GENESIS_HASH
from agnusmail.modules.audit.models import AuditChainHead, AuditEvent


class AuditEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    sequence: int
    chain_seq: int
    prev_hash: str
    event_hash: str
    event_type: str
    device_id: uuid.UUID | None
    public_key_id: uuid.UUID | None
    actor_user_id: uuid.UUID | None
    details: dict[str, Any]
    created_at: UtcDatetime

    @classmethod
    def from_event(cls, event: AuditEvent) -> "AuditEventOut":
        return cls(
            sequence=event.id,
            chain_seq=event.chain_seq,
            prev_hash=event.prev_hash.hex(),
            event_hash=event.event_hash.hex(),
            event_type=event.event_type,
            device_id=event.device_id,
            public_key_id=event.public_key_id,
            actor_user_id=event.actor_user_id,
            details=dict(event.details),
            created_at=event.created_at,
        )


class AuditEventPage(BaseModel):
    items: list[AuditEventOut]
    total: int
    limit: int
    offset: int


class AuditChainPage(BaseModel):
    """Events in chain order; continue with ``after_seq`` = last ``chain_seq``."""

    items: list[AuditEventOut]
    after_seq: int
    limit: int
    has_more: bool


class AuditChainHeadOut(BaseModel):
    """Where verification starts (checkpoint) and must end (head)."""

    version: int = CHAIN_VERSION
    algorithm: str = "sha256"
    head_seq: int
    head_hash: str
    purged_through_seq: int
    purged_through_hash: str

    @classmethod
    def from_head(cls, head: AuditChainHead | None) -> "AuditChainHeadOut":
        if head is None:
            return cls(
                head_seq=0,
                head_hash=GENESIS_HASH.hex(),
                purged_through_seq=0,
                purged_through_hash=GENESIS_HASH.hex(),
            )
        return cls(
            head_seq=head.head_seq,
            head_hash=head.head_hash.hex(),
            purged_through_seq=head.purged_through_seq,
            purged_through_hash=head.purged_through_hash.hex(),
        )
