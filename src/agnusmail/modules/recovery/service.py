"""Recovery key and encrypted backup (protocol v1 §8.2–§8.4).

The server stores the recovery certificate (public) and the client-encrypted backup of
its secret key. It never sees the 24-word phrase and never decrypts the backup: it only
checks the backup's structure (SKESK v6 + Argon2, SEIPDv2).
"""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agnusmail.core.exceptions import (
    AgnusmailError,
    ConflictError,
    InvalidStateError,
    KeyRejectedError,
    ResourceNotFoundError,
)
from agnusmail.infrastructure.openpgp import (
    CertificateRejectedError,
    EnvelopeRejectedError,
    SignatureInvalidError,
    check_recovery_backup,
    inspect_device_certificate,
    verify_detached,
)
from agnusmail.modules.audit.models import AuditEventType
from agnusmail.modules.audit.service import ActorContext, record_event
from agnusmail.modules.devices.attestation import (
    AttestationError,
    RecoveryKeyClaim,
    verify_recovery_key,
)
from agnusmail.modules.devices.models import Device
from agnusmail.modules.devices.service import AttestationRejectedError
from agnusmail.modules.identity.models import User
from agnusmail.modules.recovery.models import (
    MAX_BACKUP_BYTES,
    RecoveryBackup,
    RecoveryKey,
    RecoveryKeyStatus,
)

RECOVERY_FORMAT = "openpgp-v6/agnusmail-recovery-1"
REGISTRATION_DOMAIN = b"agnusmail/recovery-registration/v1\n"


class BackupRejectedError(AgnusmailError):
    status_code = 422
    message = "recovery backup rejected"
    code = "BACKUP_REJECTED"


def registration_statement(service: str, account: str, fingerprint: str) -> bytes:
    """Signed by the recovery certificate's signing subkey (proof of possession)."""
    return REGISTRATION_DOMAIN + f"{service}\n{account.lower()}\n{fingerprint}".encode("ascii")


@dataclass(frozen=True)
class WalletInput:
    issued_at: int
    signature: str


@dataclass(frozen=True)
class RecoveryContext:
    service: str
    chain_id: int
    max_bytes: int


def _account(session: Session, user_id: uuid.UUID) -> str:
    return session.scalars(select(User.ethereum_address).where(User.id == user_id)).one()


def active_recovery_key(session: Session, user_id: uuid.UUID) -> RecoveryKey | None:
    return session.scalars(
        select(RecoveryKey).where(
            RecoveryKey.user_id == user_id, RecoveryKey.status == RecoveryKeyStatus.ACTIVE
        )
    ).one_or_none()


def register_recovery_key(
    session: Session,
    actor: ActorContext,
    material: bytes,
    proof: bytes,
    wallet: WalletInput,
    ctx: RecoveryContext,
    now: datetime,
) -> RecoveryKey:
    """Publish (or replace) the account's recovery certificate (spec §8.2).

    Replacing it does not re-wrap old messages: the client must do that (§6.4) while it
    still holds the previous recovery key.
    """
    if not material or len(material) > ctx.max_bytes:
        raise KeyRejectedError(f"recovery certificate must be 1..{ctx.max_bytes} bytes")
    try:
        info = inspect_device_certificate(material, now=now)
    except CertificateRejectedError as exc:
        raise KeyRejectedError(f"invalid recovery certificate: {exc.reason}") from exc
    account = _account(session, actor.user_id)
    statement = registration_statement(ctx.service, account, info.fingerprint)
    try:
        signer = verify_detached(material, statement, proof)
    except SignatureInvalidError as exc:
        raise KeyRejectedError("proof of possession does not verify") from exc
    if signer != info.signing_fingerprint:
        raise KeyRejectedError("proof of possession must be made by the signing subkey")
    try:
        verify_recovery_key(
            RecoveryKeyClaim(account, info.fingerprint, ctx.service, wallet.issued_at),
            bytes.fromhex(wallet.signature.removeprefix("0x")),
            chain_id=ctx.chain_id,
            now=now,
        )
    except AttestationError as exc:
        raise AttestationRejectedError(f"recovery key certificate rejected: {exc.reason}") from exc

    session.execute(select(User.id).where(User.id == actor.user_id).with_for_update())
    used = session.scalar(
        select(func.count()).select_from(Device).where(Device.fingerprint == info.fingerprint)
    ) or session.scalar(
        select(func.count())
        .select_from(RecoveryKey)
        .where(RecoveryKey.fingerprint == info.fingerprint)
    )
    if used:
        raise ConflictError("this certificate is already in use")
    previous = active_recovery_key(session, actor.user_id)
    if previous is not None:
        previous.status = RecoveryKeyStatus.REPLACED
        previous.replaced_at = now
        session.flush()
    key = RecoveryKey(
        user_id=actor.user_id,
        material=material,
        fingerprint=info.fingerprint,
        signing_fingerprint=info.signing_fingerprint,
        encryption_fingerprint=info.encryption_fingerprint,
        expires_at=info.expires_at,
        wallet_account=account,
        wallet_signature=wallet.signature.lower(),
        wallet_issued_at=datetime.fromtimestamp(wallet.issued_at, tz=UTC),
        status=RecoveryKeyStatus.ACTIVE,
    )
    session.add(key)
    session.flush()
    record_event(
        session,
        actor,
        AuditEventType.RECOVERY_KEY_REGISTERED,
        owner_id=actor.user_id,
        details={"fingerprint": info.fingerprint, "replaced": previous is not None},
    )
    return key


def store_backup(session: Session, actor: ActorContext, blob: bytes) -> RecoveryBackup:
    """A new version of the encrypted backup, tied to the active recovery key."""
    if not blob or len(blob) > MAX_BACKUP_BYTES:
        raise BackupRejectedError(f"backup must be 1..{MAX_BACKUP_BYTES} bytes")
    try:
        check_recovery_backup(blob)
    except EnvelopeRejectedError as exc:
        raise BackupRejectedError(exc.reason) from exc
    session.execute(select(User.id).where(User.id == actor.user_id).with_for_update())
    key = active_recovery_key(session, actor.user_id)
    if key is None:
        raise InvalidStateError("register a recovery key first")
    latest = session.scalar(
        select(func.max(RecoveryBackup.version)).where(RecoveryBackup.user_id == actor.user_id)
    )
    backup = RecoveryBackup(
        user_id=actor.user_id, recovery_key_id=key.id, version=int(latest or 0) + 1, blob=blob
    )
    session.add(backup)
    session.flush()
    record_event(
        session,
        actor,
        AuditEventType.RECOVERY_BACKUP_STORED,
        owner_id=actor.user_id,
        details={"version": backup.version, "fingerprint": key.fingerprint},
    )
    return backup


def latest_backup(session: Session, user_id: uuid.UUID) -> RecoveryBackup:
    backup = session.scalars(
        select(RecoveryBackup)
        .where(RecoveryBackup.user_id == user_id)
        .order_by(RecoveryBackup.version.desc())
        .limit(1)
    ).one_or_none()
    if backup is None:
        raise ResourceNotFoundError("no backup")
    return backup
