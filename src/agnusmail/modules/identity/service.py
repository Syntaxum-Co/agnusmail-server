"""Identity use cases executed outside the event loop (sync SQLAlchemy sessions)."""

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.core.exceptions import DatabaseUnavailableError
from agnusmail.core.logging import get_logger
from agnusmail.extensions import AccountCreatedHook
from agnusmail.modules.audit.models import AuditEventType
from agnusmail.modules.audit.service import ActorContext, record_event
from agnusmail.modules.identity.models import UserStatus
from agnusmail.modules.identity.repository import register_login

log = get_logger(__name__)


@dataclass(frozen=True)
class LoginOutcome:
    user_id: uuid.UUID
    active: bool


def record_login(
    session_factory: sessionmaker[Session],
    address: str,
    *,
    session_id: str,
    client: dict[str, str] | None = None,
    on_account_created: Sequence[AccountCreatedHook] = (),
) -> LoginOutcome:
    """Register the address on first login, stamp last_login_at and audit the attempt.

    All in one transaction: a login is never recorded without its audit event. A
    suspended account gets an ``auth.login_denied`` event instead of ``auth.login``.
    ``on_account_created`` hooks (from extensions) run in the same transaction when this
    login creates the account.
    """
    try:
        with session_factory() as session, session.begin():
            now = datetime.now(UTC)
            user, created = register_login(session, address, now)
            if created:
                for hook in on_account_created:
                    hook(session, user, now)
            active = user.status == UserStatus.ACTIVE
            record_event(
                session,
                ActorContext(user_id=user.id, client=dict(client or {})),
                AuditEventType.AUTH_LOGIN if active else AuditEventType.AUTH_LOGIN_DENIED,
                owner_id=user.id,
                details=(
                    {"session": session_id, "method": "siwe"}
                    if active
                    else {"reason": "account_suspended", "method": "siwe"}
                ),
            )
            return LoginOutcome(user_id=user.id, active=active)
    except SQLAlchemyError as exc:
        log.error("login_persistence_failed", error_type=type(exc).__name__)
        raise DatabaseUnavailableError() from exc
