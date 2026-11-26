"""Public key directory use cases. Synchronous; run inside ``run_in_transaction``.

Publication rule: the directory only returns ACTIVE, unexpired keys of ACTIVE devices
of ACTIVE users. A key uploaded to a pending device is stored but not published until
the device is authorized.

Registration validates the OpenPGP v6 certificate and the proof of possession
(``policy.py``, protocol v1 §3). The device's primary-key fingerprint is fixed by its
first certificate; later versions must keep the same primary key (spec §3.4).
Transparency log (RFC 9162): deferred.
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agnusmail.core.exceptions import (
    ConflictError,
    DeviceKeyInUseError,
    InvalidStateError,
    KeyRejectedError,
    LimitExceededError,
    ReauthenticationRequiredError,
    ResourceNotFoundError,
)
from agnusmail.modules.audit.models import AuditEventType
from agnusmail.modules.audit.service import ActorContext, record_event
from agnusmail.modules.devices.models import Device, DeviceStatus
from agnusmail.modules.devices.service import get_owned_device
from agnusmail.modules.identity.models import UserStatus
from agnusmail.modules.identity.repository import get_by_address
from agnusmail.modules.keys.models import PublicKey, PublicKeyStatus
from agnusmail.modules.keys.policy import (
    KeyMaterialPolicy,
    RegistrationContext,
    material_digest,
)
from agnusmail.modules.recovery.models import (
    AccountMigration,
    MigrationStatus,
    RecoveryKey,
    RecoveryKeyStatus,
)


@dataclass(frozen=True)
class KeyLimits:
    max_keys_per_device: int


def _key_details(key: PublicKey, **extra: object) -> dict[str, object]:
    return {
        "version": key.version,
        "format": key.format,
        "material_digest": key.material_digest,
        "fingerprint": key.fingerprint,
        **extra,
    }


def register_key(
    session: Session,
    actor: ActorContext,
    device_id: uuid.UUID,
    key_format: str,
    material: bytes,
    proof: bytes,
    *,
    policy: KeyMaterialPolicy,
    context: RegistrationContext,
    limits: KeyLimits,
    recently_authenticated: bool,
) -> PublicKey:
    """Store a new certificate version for the device, superseding the active one."""
    info = policy.check(key_format, material, proof, context)
    now = context.now
    device = get_owned_device(session, actor.user_id, device_id, lock=True)
    if device.status == DeviceStatus.REVOKED:
        raise InvalidStateError("device is revoked")
    if device.fingerprint is None:
        taken = session.scalar(select(Device.id).where(Device.fingerprint == info.fingerprint))
        if taken is not None:
            raise DeviceKeyInUseError()
        device.fingerprint = info.fingerprint
    elif device.fingerprint != info.fingerprint:
        raise KeyRejectedError("a new version must keep the device's primary key")
    if device.status == DeviceStatus.ACTIVE and not recently_authenticated:
        # Publishing to an active device takes effect immediately: same bar as authorizing.
        raise ReauthenticationRequiredError()

    total = session.scalar(
        select(func.count()).select_from(PublicKey).where(PublicKey.device_id == device.id)
    )
    if int(total or 0) >= limits.max_keys_per_device:
        raise LimitExceededError("key version limit reached for this device")

    digest = material_digest(material)
    duplicate = session.scalar(
        select(PublicKey.id).where(
            PublicKey.user_id == actor.user_id, PublicKey.material_digest == digest
        )
    )
    if duplicate is not None:
        raise ConflictError("this public key is already registered for the account")

    latest = session.scalar(
        select(func.max(PublicKey.version)).where(PublicKey.device_id == device.id)
    )
    version = int(latest or 0) + 1

    previous = session.scalars(
        select(PublicKey)
        .where(
            PublicKey.device_id == device.id,
            PublicKey.format == key_format,
            PublicKey.status == PublicKeyStatus.ACTIVE,
        )
        .with_for_update()
    ).one_or_none()
    if previous is not None:
        previous.status = PublicKeyStatus.SUPERSEDED
        previous.superseded_at = now
        session.flush()  # free the "one active per (device, format)" slot first
        record_event(
            session,
            actor,
            AuditEventType.KEY_SUPERSEDED,
            owner_id=actor.user_id,
            device_id=device.id,
            public_key_id=previous.id,
            details=_key_details(previous, superseded_by_version=version),
        )

    key = PublicKey(
        user_id=actor.user_id,
        device_id=device.id,
        version=version,
        format=key_format,
        material=material,
        material_digest=digest,
        status=PublicKeyStatus.ACTIVE,
        fingerprint=info.fingerprint,
        signing_fingerprint=info.signing_fingerprint,
        encryption_fingerprint=info.encryption_fingerprint,
        expires_at=info.expires_at,
    )
    session.add(key)
    session.flush()
    record_event(
        session,
        actor,
        AuditEventType.KEY_REGISTERED,
        owner_id=actor.user_id,
        device_id=device.id,
        public_key_id=key.id,
        details=_key_details(key, device_status=device.status),
    )
    return key


def list_device_keys(
    session: Session, owner_id: uuid.UUID, device_id: uuid.UUID, *, limit: int, offset: int
) -> tuple[list[PublicKey], int]:
    """Every version of the device's keys (any status), newest version first."""
    get_owned_device(session, owner_id, device_id)
    condition = PublicKey.device_id == device_id
    total = session.scalar(select(func.count()).select_from(PublicKey).where(condition))
    rows = session.scalars(
        select(PublicKey)
        .where(condition)
        .order_by(PublicKey.version.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return list(rows), int(total or 0)


def revoke_key(
    session: Session,
    actor: ActorContext,
    device_id: uuid.UUID,
    key_id: uuid.UUID,
    now: datetime,
) -> PublicKey:
    device = get_owned_device(session, actor.user_id, device_id, lock=True)
    key = session.scalars(
        select(PublicKey)
        .where(
            PublicKey.id == key_id,
            PublicKey.device_id == device.id,
            PublicKey.user_id == actor.user_id,
        )
        .with_for_update()
    ).one_or_none()
    if key is None:
        raise ResourceNotFoundError("key not found")
    if key.status == PublicKeyStatus.REVOKED:
        raise InvalidStateError("key is already revoked")
    previous = key.status
    key.status = PublicKeyStatus.REVOKED
    key.revoked_at = now
    session.flush()
    record_event(
        session,
        actor,
        AuditEventType.KEY_REVOKED,
        owner_id=actor.user_id,
        device_id=device.id,
        public_key_id=key.id,
        details=_key_details(key, **{"from": previous, "cause": "user_request"}),
    )
    return key


@dataclass(frozen=True)
class DirectoryView:
    """What senders need to verify the account's devices themselves (spec §4.3)."""

    entries: list[tuple[PublicKey, Device]]
    wallet_revocations: list[Device]
    recovery_key: RecoveryKey | None = None
    migrations: list[AccountMigration] = field(default_factory=list)


def lookup_directory(session: Session, address: str, now: datetime) -> DirectoryView:
    """Published keys for an address. Unknown and keyless addresses look the same (empty).

    A key is published only while its OpenPGP certificate and its device's wallet
    certificate are both unexpired.
    """
    user = get_by_address(session, address)
    if user is None or user.status != UserStatus.ACTIVE:
        return DirectoryView([], [])
    rows = session.execute(
        select(PublicKey, Device)
        .join(Device, Device.id == PublicKey.device_id)
        .where(
            PublicKey.user_id == user.id,
            PublicKey.status == PublicKeyStatus.ACTIVE,
            PublicKey.expires_at > now,  # also hides interim rows without an expiry
            Device.status == DeviceStatus.ACTIVE,
            Device.certificate_expires_at > now,
        )
        .order_by(Device.created_at, PublicKey.format)
    ).all()
    revoked = session.scalars(
        select(Device)
        .where(Device.user_id == user.id, Device.wallet_revocation_signature.is_not(None))
        .order_by(Device.wallet_revoked_at)
    ).all()
    recovery = session.scalars(
        select(RecoveryKey).where(
            RecoveryKey.user_id == user.id,
            RecoveryKey.status == RecoveryKeyStatus.ACTIVE,
            RecoveryKey.expires_at > now,
        )
    ).one_or_none()
    migrations = list(
        session.scalars(
            select(AccountMigration)
            .where(
                AccountMigration.user_id == user.id,
                AccountMigration.status == MigrationStatus.COMPLETED,
            )
            .order_by(AccountMigration.finished_at)
        )
    )
    return DirectoryView([(row[0], row[1]) for row in rows], list(revoked), recovery, migrations)
