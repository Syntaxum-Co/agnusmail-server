"""Request dependencies: authenticated session and per-route/per-user rate limits.

Every authenticated route depends on ``CurrentSession``, which validates the session
cookie and applies the per-user rate limit, so new routes get both automatically.
Rate-limit backend failures fail open (same policy as the per-IP middleware).
"""

import time
import uuid
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Request
from fastapi.concurrency import run_in_threadpool
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.core.config import Settings
from agnusmail.core.exceptions import (
    AccountSuspendedError,
    NotAuthenticatedError,
    RateLimitedError,
    ReauthenticationRequiredError,
    SessionRevokedError,
)
from agnusmail.core.logging import get_logger
from agnusmail.core.security import session_cookie_name
from agnusmail.modules.audit.models import AuditEventType
from agnusmail.modules.audit.service import ActorContext
from agnusmail.modules.authentication.audit import audit_session_event
from agnusmail.modules.authentication.stores import SessionRecord, SessionStore
from agnusmail.modules.authentication.suspicious import Verdict, evaluate, fingerprint
from agnusmail.modules.identity.models import User, UserStatus

log = get_logger(__name__)


@dataclass(frozen=True)
class SessionContext:
    token: str
    record: SessionRecord

    @property
    def user_id(self) -> str:
        return self.record.owner


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


async def enforce_rate_limit(request: Request, key: str, limit: int) -> None:
    settings: Settings = request.app.state.settings
    try:
        allowed = await request.app.state.rate_limiter.check(
            key, limit, settings.rate_limit_window_seconds
        )
    except Exception:
        request.app.state.rate_limit_failures.report()
        return
    if not allowed:
        raise RateLimitedError()


async def auth_rate_limit(request: Request) -> None:
    """Tighter per-IP budget for the unauthenticated login routes."""
    settings: Settings = request.app.state.settings
    await enforce_rate_limit(
        request, f"auth:ip:{client_ip(request)}", settings.rate_limit_auth_per_ip
    )


def session_token(request: Request) -> str | None:
    return request.cookies.get(session_cookie_name(request.app.state.settings))


async def current_session(request: Request) -> SessionContext:
    """Resolve the caller's session (401 otherwise) and apply the per-user rate limit."""
    token = session_token(request)
    if not token:
        raise NotAuthenticatedError()
    store: SessionStore = request.app.state.session_store
    record = await store.get(token)
    if record is None:
        raise NotAuthenticatedError()
    settings: Settings = request.app.state.settings
    await check_session_fingerprint(request, settings, store, token, record)
    await check_account_active(request, store, token, record)
    await enforce_rate_limit(request, f"user:{record.owner}", settings.rate_limit_per_user)
    return SessionContext(token=token, record=record)


def request_fingerprint(request: Request) -> dict[str, str]:
    return fingerprint(request.headers.get("user-agent", ""), client_ip(request))


async def check_session_fingerprint(
    request: Request,
    settings: Settings,
    store: SessionStore,
    token: str,
    record: SessionRecord,
) -> None:
    """Revoke sessions replayed from another client; log network changes."""
    current = request_fingerprint(request)
    verdict = evaluate(record.fingerprint, current)
    if verdict is Verdict.USER_AGENT_CHANGED and settings.session_bind_user_agent:
        await store.revoke(token)
        log.warning(
            "session_suspicious", reason=verdict.value, user_id=record.owner, action="revoked"
        )
        await audit_session_event(
            request,
            record.owner,
            AuditEventType.AUTH_SESSION_REVOKED,
            actor_client=None,  # the system revoked it; the presenter is not the owner
            details={
                "session": record.data.get("session_id"),
                "reason": verdict.value,
                "observed_client": current,
            },
        )
        raise SessionRevokedError()
    if verdict is not Verdict.OK:
        log.warning(
            "session_suspicious", reason=verdict.value, user_id=record.owner, action="logged"
        )
        await store.update_fingerprint(token, current)


async def check_account_active(
    request: Request, store: SessionStore, token: str, record: SessionRecord
) -> None:
    """End the session of a suspended account on its next request.

    A database failure skips the check: every route that reads or changes data needs the
    database and answers 503 on its own, so nothing is served from a stale status.
    """
    factory: sessionmaker[Session] | None = request.app.state.db_session_factory
    if factory is None:
        return
    owner = uuid.UUID(record.owner)

    def status() -> str | None:
        with factory() as session:
            return session.scalar(select(User.status).where(User.id == owner))

    try:
        current = await run_in_threadpool(status)
    except SQLAlchemyError as exc:
        log.warning("account_status_check_skipped", error_type=type(exc).__name__)
        return
    if current != UserStatus.ACTIVE:
        await store.revoke(token)
        log.warning("session_of_inactive_account", user_id=record.owner, action="revoked")
        raise AccountSuspendedError()


CurrentSession = Annotated[SessionContext, Depends(current_session)]


async def recent_session(request: Request, session: CurrentSession) -> SessionContext:
    """Step-up: the session must come from a login within the configured window.

    Used for sensitive changes (e.g. authorizing a device) so that an old or stolen
    session cannot perform them without a fresh SIWE signature.
    """
    if not is_recently_authenticated(request, session):
        raise ReauthenticationRequiredError()
    return session


def is_recently_authenticated(request: Request, session: SessionContext) -> bool:
    """True when the session's SIWE login happened within the step-up window."""
    settings: Settings = request.app.state.settings
    return time.time() - session.record.created_at <= settings.step_up_max_auth_age_seconds


RecentSession = Annotated[SessionContext, Depends(recent_session)]


def actor_context(request: Request, session: SessionContext) -> ActorContext:
    """Audit actor for the current request: user id + hashed client fingerprint."""
    return ActorContext(user_id=uuid.UUID(session.user_id), client=request_fingerprint(request))


def db_session_factory(request: Request) -> sessionmaker[Session] | None:
    return request.app.state.db_session_factory  # type: ignore[no-any-return]


DbSessionFactory = Annotated[sessionmaker[Session] | None, Depends(db_session_factory)]
