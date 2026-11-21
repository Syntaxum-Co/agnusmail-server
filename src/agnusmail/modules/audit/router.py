"""The caller's own audit chain (/v1/audit), for client-side verification.

A client verifies from the checkpoint (``purged_through_*``) to the head and remembers the
head hash; a later answer that does not extend it reveals rewritten history.
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Query
from sqlalchemy.orm import Session

from agnusmail.infrastructure.database.transaction import run_in_transaction
from agnusmail.modules.audit.schemas import AuditChainHeadOut, AuditChainPage, AuditEventOut
from agnusmail.modules.audit.service import get_chain_head, list_chain
from agnusmail.modules.authentication.dependencies import CurrentSession, DbSessionFactory

router = APIRouter(prefix="/audit", tags=["audit"])

Limit = Annotated[int, Query(ge=1, le=200)]
AfterSeq = Annotated[int, Query(ge=0, le=2**62)]


@router.get("/chain")
async def chain_head(session: CurrentSession, db: DbSessionFactory) -> AuditChainHeadOut:
    owner = uuid.UUID(session.user_id)
    return await run_in_transaction(
        db, lambda s: AuditChainHeadOut.from_head(get_chain_head(s, owner))
    )


@router.get("/events")
async def chain_events(
    session: CurrentSession, db: DbSessionFactory, after_seq: AfterSeq = 0, limit: Limit = 100
) -> AuditChainPage:
    """The caller's events in chain order (oldest first), after ``after_seq``."""
    owner = uuid.UUID(session.user_id)

    def work(s: Session) -> AuditChainPage:
        events = list_chain(s, owner, after_seq=after_seq, limit=limit + 1)
        return AuditChainPage(
            items=[AuditEventOut.from_event(e) for e in events[:limit]],
            after_seq=after_seq,
            limit=limit,
            has_more=len(events) > limit,
        )

    return await run_in_transaction(db, work)
