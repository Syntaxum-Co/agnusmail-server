"""Storage usage API: ``GET /v1/usage`` returns the caller's stored bytes and limit."""

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Request
from pydantic import BaseModel

from agnusmail.infrastructure.database.transaction import run_in_transaction
from agnusmail.modules.authentication.dependencies import CurrentSession, DbSessionFactory
from agnusmail.modules.quotas.policy import QuotaPolicy

router = APIRouter(tags=["usage"])


class UsageOut(BaseModel):
    stored_bytes: int
    quota_bytes: int
    full: bool


@router.get("/usage")
async def usage(request: Request, session: CurrentSession, db: DbSessionFactory) -> UsageOut:
    policy: QuotaPolicy = request.app.state.quota_policy
    owner = uuid.UUID(session.user_id)
    now = datetime.now(UTC)
    standing = await run_in_transaction(db, lambda s: policy.standing(s, owner, now))
    return UsageOut(
        stored_bytes=standing.stored_bytes,
        quota_bytes=standing.quota_bytes,
        full=standing.full,
    )
