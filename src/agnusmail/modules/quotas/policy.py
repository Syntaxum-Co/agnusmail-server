"""Who may send, upload and receive, and how much.

Every active account gets the same storage limit (``storage_quota_bytes``). Over the
limit, or suspended, only what grows is refused: reading, moving and deleting always
work, and nothing is ever deleted to make room.
"""

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agnusmail.core.config import Settings
from agnusmail.core.exceptions import AgnusmailError
from agnusmail.modules.identity.models import User, UserStatus
from agnusmail.modules.quotas.usage import lock_usage, stored_bytes


class AccountSuspendedError(AgnusmailError):
    status_code = 403
    message = "account suspended"
    code = "ACCOUNT_SUSPENDED"


class QuotaExceededError(AgnusmailError):
    status_code = 409
    message = "storage limit reached: delete messages from the trash to free space"
    code = "QUOTA_EXCEEDED"


class RecipientMailboxUnavailableError(AgnusmailError):
    """The recipient cannot receive now (suspended, or storage full)."""

    status_code = 409
    message = "a recipient's mailbox cannot receive messages right now"
    code = "RECIPIENT_MAILBOX_UNAVAILABLE"


@dataclass(frozen=True)
class Standing:
    active: bool
    stored_bytes: int
    quota_bytes: int

    @property
    def full(self) -> bool:
        return self.stored_bytes >= self.quota_bytes


@dataclass(frozen=True)
class QuotaPolicy:
    quota_bytes: int

    @classmethod
    def from_settings(cls, settings: Settings) -> "QuotaPolicy":
        return cls(quota_bytes=settings.storage_quota_bytes)

    def standing(self, session: Session, user_id: uuid.UUID, now: datetime) -> Standing:
        del now  # kept so callers do not depend on how the policy decides
        status = session.scalar(select(User.status).where(User.id == user_id))
        return Standing(
            active=status == UserStatus.ACTIVE,
            stored_bytes=stored_bytes(session, user_id),
            quota_bytes=self.quota_bytes,
        )

    def require_active(self, session: Session, user_id: uuid.UUID, now: datetime) -> Standing:
        standing = self.standing(session, user_id, now)
        if not standing.active:
            raise AccountSuspendedError()
        return standing

    def require_space(
        self, session: Session, user_id: uuid.UUID, extra_bytes: int, now: datetime
    ) -> None:
        """The account itself adds ``extra_bytes`` (send, upload, portal). The usage row
        is locked until the transaction ends, so concurrent writers of one account are
        checked one after the other; uploads not confirmed yet count as reserved."""
        from agnusmail.modules.attachments.models import Attachment, AttachmentStatus

        lock_usage(session, user_id)
        standing = self.require_active(session, user_id, now)
        pending = session.scalar(
            select(func.coalesce(func.sum(Attachment.size), 0)).where(
                Attachment.owner_id == user_id, Attachment.status == AttachmentStatus.PENDING
            )
        )
        if standing.stored_bytes + int(pending or 0) + extra_bytes > standing.quota_bytes:
            raise QuotaExceededError()

    def accepts(
        self, session: Session, user_id: uuid.UUID, extra_bytes: int, now: datetime
    ) -> bool:
        """Whether the account can receive ``extra_bytes`` from someone else."""
        standing = self.standing(session, user_id, now)
        return (
            standing.active
            and not standing.full  # a full mailbox takes nothing, not even 0 bytes (RCPT)
            and standing.stored_bytes + extra_bytes <= standing.quota_bytes
        )

    def require_recipient(
        self, session: Session, user_id: uuid.UUID, extra_bytes: int, now: datetime
    ) -> None:
        if not self.accepts(session, user_id, extra_bytes, now):
            raise RecipientMailboxUnavailableError()
