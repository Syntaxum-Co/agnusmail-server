"""Audit events for session changes that happen in Redis, outside a DB transaction.

Logout, suspicious-session revocation and replacement by a new login are written AFTER
the Redis change, best effort: a database failure is logged and never blocks the
security action itself (a logout must always succeed). Logins are audited atomically
in ``identity.service.record_login`` instead.
"""

import uuid
from typing import Any

from fastapi import Request
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.core.logging import get_logger
from agnusmail.modules.audit.models import AuditEventType
from agnusmail.modules.audit.service import ActorContext, record_event

log = get_logger(__name__)


def _write(
    factory: sessionmaker[Session] | None,
    owner_id: uuid.UUID,
    event_type: AuditEventType,
    actor: ActorContext | None,
    details: dict[str, Any],
) -> None:
    if factory is None:
        raise RuntimeError("database not configured")
    with factory() as session, session.begin():
        record_event(session, actor, event_type, owner_id=owner_id, details=details)


async def audit_session_event(
    request: Request,
    owner: str,
    event_type: AuditEventType,
    *,
    actor_client: dict[str, str] | None,
    details: dict[str, Any],
) -> bool:
    """Best-effort append. ``actor_client=None`` records the system as the actor."""
    try:
        owner_id = uuid.UUID(owner)
        actor = None if actor_client is None else ActorContext(owner_id, dict(actor_client))
        await run_in_threadpool(
            _write, request.app.state.db_session_factory, owner_id, event_type, actor, details
        )
    except Exception as exc:  # the session change already happened; never undo it
        log.error("audit_write_failed", event_type=str(event_type), error_type=type(exc).__name__)
        return False
    return True
