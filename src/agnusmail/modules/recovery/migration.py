"""Moving an account to a new wallet after losing the old one (spec §8.5).

1. Request (no session — the old wallet is lost): a signature by the recovery
   certificate's signing subkey over the migration statement, plus an EIP-712
   ``AccountMigrationAcceptance`` signed by the NEW wallet. The recovery certificate
   must have been attested by the old wallet.
2. Seven days of waiting; the request is an event in the account's audit chain, and any
   session of the account can cancel it.
3. A worker job completes it: the account's address becomes the new wallet's and every
   session of the account ends. Completed migrations are public evidence for senders
   (old wallet → RecoveryKeyCertificate → migration → new wallet).
"""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from agnusmail.core.exceptions import (
    AgnusmailError,
    ConflictError,
    InvalidStateError,
    ResourceNotFoundError,
)
from agnusmail.infrastructure.openpgp import SignatureInvalidError, verify_detached
from agnusmail.modules.audit.models import AuditEventType
from agnusmail.modules.audit.service import ActorContext, record_event
from agnusmail.modules.devices.attestation import (
    AttestationError,
    MigrationAcceptanceClaim,
    verify_migration_acceptance,
)
from agnusmail.modules.identity.models import User, UserStatus
from agnusmail.modules.identity.repository import get_by_address
from agnusmail.modules.recovery.models import AccountMigration, MigrationStatus
from agnusmail.modules.recovery.service import RecoveryContext, active_recovery_key

MIGRATION_DOMAIN = "agnusmail/account-migration/v1"
MIGRATION_WAIT = timedelta(days=7)
REQUEST_MAX_AGE = timedelta(minutes=10)
CLOCK_SKEW = timedelta(minutes=5)


class MigrationRejectedError(AgnusmailError):
    """One answer for every rejected request: no hint about which proof failed."""

    status_code = 422
    message = "account migration rejected"
    code = "MIGRATION_REJECTED"


def migration_statement(service: str, old_account: str, new_account: str, issued_at: int) -> bytes:
    """Signed by the recovery certificate's signing subkey."""
    parts = [MIGRATION_DOMAIN, service, old_account.lower(), new_account.lower(), str(issued_at)]
    return "\n".join(parts).encode("ascii")


@dataclass(frozen=True)
class MigrationRequest:
    old_account: str
    new_account: str
    issued_at: int
    recovery_signature: bytes
    acceptance_signature: str


def request_migration(
    session: Session, request: MigrationRequest, ctx: RecoveryContext, now: datetime
) -> AccountMigration:
    old = request.old_account.lower()
    new = request.new_account.lower()
    issued = datetime.fromtimestamp(request.issued_at, tz=UTC)
    if old == new or not now - REQUEST_MAX_AGE <= issued <= now + CLOCK_SKEW:
        raise MigrationRejectedError()
    user = get_by_address(session, old)
    if user is None or user.status != UserStatus.ACTIVE:
        raise MigrationRejectedError()
    key = active_recovery_key(session, user.id)
    if key is None or key.wallet_account.lower() != old:
        raise MigrationRejectedError()  # the recovery key must be attested by this wallet
    statement = migration_statement(ctx.service, old, new, request.issued_at)
    try:
        signer = verify_detached(key.material, statement, request.recovery_signature)
        verify_migration_acceptance(
            MigrationAcceptanceClaim(old, new, key.fingerprint, ctx.service, request.issued_at),
            bytes.fromhex(request.acceptance_signature.removeprefix("0x")),
            chain_id=ctx.chain_id,
        )
    except (SignatureInvalidError, AttestationError, ValueError) as exc:
        raise MigrationRejectedError() from exc
    if signer != key.signing_fingerprint:
        raise MigrationRejectedError()
    if get_by_address(session, new) is not None:
        raise ConflictError("the new wallet already has an account")
    session.execute(select(User.id).where(User.id == user.id).with_for_update())
    pending = session.scalar(
        select(AccountMigration.id).where(
            AccountMigration.user_id == user.id,
            AccountMigration.status == MigrationStatus.PENDING,
        )
    )
    if pending is not None:
        raise ConflictError("a migration is already pending")
    migration = AccountMigration(
        user_id=user.id,
        recovery_key_id=key.id,
        old_account=old,
        new_account=new,
        issued_at=issued,
        recovery_signature=request.recovery_signature,
        acceptance_signature=request.acceptance_signature.lower(),
        status=MigrationStatus.PENDING,
        requested_at=now,
        effective_at=now + MIGRATION_WAIT,
    )
    session.add(migration)
    session.flush()
    record_event(
        session,
        None,  # nobody is logged in: the system records the request
        AuditEventType.RECOVERY_MIGRATION_REQUESTED,
        owner_id=user.id,
        details={
            "migration": str(migration.id),
            "new_account": new,
            "effective_at": migration.effective_at.isoformat(),
        },
    )
    return migration


def list_migrations(session: Session, user_id: uuid.UUID) -> list[AccountMigration]:
    rows = session.scalars(
        select(AccountMigration)
        .where(AccountMigration.user_id == user_id)
        .order_by(AccountMigration.requested_at.desc())
    )
    return list(rows)


def cancel_migration(
    session: Session, actor: ActorContext, migration_id: uuid.UUID, now: datetime
) -> AccountMigration:
    migration = session.scalars(
        select(AccountMigration)
        .where(AccountMigration.id == migration_id, AccountMigration.user_id == actor.user_id)
        .with_for_update()
    ).one_or_none()
    if migration is None:
        raise ResourceNotFoundError("migration not found")
    if migration.status != MigrationStatus.PENDING:
        raise InvalidStateError(f"migration is {migration.status}")
    migration.status = MigrationStatus.CANCELLED
    migration.finished_at = now
    session.flush()
    record_event(
        session,
        actor,
        AuditEventType.RECOVERY_MIGRATION_CANCELLED,
        owner_id=actor.user_id,
        details={"migration": str(migration.id), "new_account": migration.new_account},
    )
    return migration


def complete_due_migrations(session: Session, now: datetime) -> list[AccountMigration]:
    """Worker: move accounts whose waiting period ended to the new wallet."""
    due = session.scalars(
        select(AccountMigration)
        .where(
            AccountMigration.status == MigrationStatus.PENDING,
            AccountMigration.effective_at <= now,
        )
        .with_for_update(skip_locked=True)
    ).all()
    done: list[AccountMigration] = []
    for migration in due:
        user = session.get(User, migration.user_id, with_for_update=True)
        assert user is not None
        if get_by_address(session, migration.new_account) is not None:
            # The new wallet opened an account meanwhile: never merge accounts silently.
            migration.status = MigrationStatus.CANCELLED
            migration.finished_at = now
            continue
        user.ethereum_address = migration.new_account
        migration.status = MigrationStatus.COMPLETED
        migration.finished_at = now
        session.flush()
        record_event(
            session,
            None,
            AuditEventType.RECOVERY_MIGRATION_COMPLETED,
            owner_id=user.id,
            details={
                "migration": str(migration.id),
                "old_account": migration.old_account,
                "new_account": migration.new_account,
            },
        )
        done.append(migration)
    return done


def completed_migrations(session: Session, user_id: uuid.UUID) -> list[AccountMigration]:
    """Public evidence chain for senders (spec §8.5 step 3)."""
    rows = session.scalars(
        select(AccountMigration)
        .where(
            AccountMigration.user_id == user_id,
            AccountMigration.status == MigrationStatus.COMPLETED,
        )
        .order_by(AccountMigration.finished_at)
    )
    return list(rows)
