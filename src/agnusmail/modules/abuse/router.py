"""Abuse API.

- ``POST /v1/messages/{id}/report``: report the sender of a message you hold (metadata
  only: the category; never any content).
- ``GET /v1/abuse/status``: whether your account is restricted, why and until when.
"""

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from agnusmail.core.config import Settings
from agnusmail.core.schemas import UtcDatetime
from agnusmail.infrastructure.database.transaction import run_in_transaction
from agnusmail.modules.abuse import service
from agnusmail.modules.abuse.models import ReportCategory
from agnusmail.modules.authentication.dependencies import (
    CurrentSession,
    DbSessionFactory,
    actor_context,
)

router = APIRouter(tags=["abuse"])


class ReportIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    category: ReportCategory = Field(strict=False)


class ReportOut(BaseModel):
    id: uuid.UUID
    category: str
    created_at: UtcDatetime


class StatusOut(BaseModel):
    restricted: bool
    reason: str | None
    restricted_until: UtcDatetime | None


@router.post("/messages/{message_id}/report", status_code=201)
async def report_message(
    request: Request,
    message_id: uuid.UUID,
    payload: ReportIn,
    session: CurrentSession,
    db: DbSessionFactory,
) -> ReportOut:
    settings: Settings = request.app.state.settings
    actor = actor_context(request, session)
    thresholds = service.Thresholds.from_settings(settings)
    now = datetime.now(UTC)

    def work(s: Session) -> ReportOut:
        row = service.report(s, actor, message_id, payload.category, thresholds, now)
        return ReportOut(id=row.id, category=row.category, created_at=row.created_at)

    return await run_in_transaction(db, work)


@router.get("/abuse/status")
async def status(session: CurrentSession, db: DbSessionFactory) -> StatusOut:
    owner = uuid.UUID(session.user_id)
    now = datetime.now(UTC)

    def work(s: Session) -> StatusOut:
        row = service.restriction(s, owner, now)
        if row is None:
            return StatusOut(restricted=False, reason=None, restricted_until=None)
        return StatusOut(restricted=True, reason=row.reason, restricted_until=row.restricted_until)

    return await run_in_transaction(db, work)
