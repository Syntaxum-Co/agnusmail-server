"""Device use cases. Synchronous; run inside ``run_in_transaction``.

Authorization model: every query is scoped to the acting user. A device that does not
exist and a device owned by someone else are indistinguishable (404), so device ids
cannot be probed (anti-IDOR / anti-enumeration).

Trust: a device becomes active only with an EIP-712 DeviceCertificate signed by the
account's wallet over the v6 fingerprint of its primary key (protocol v1 §4, 4.D.4).
"""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agnusmail.core.exceptions import (
    AgnusmailError,
    InvalidStateError,
    LimitExceededError,
    ResourceNotFoundError,
)
from agnusmail.modules.audit.models import AuditEventType
from agnusmail.modules.audit.service import ActorContext, record_event
from agnusmail.modules.devices.attestation import (
    AttestationError,
    DeviceCertificateClaim,
    DeviceRevocationClaim,
    verify_device_certificate,
    verify_device_revocation,
)
from agnusmail.modules.devices.models import Device, DeviceStatus
from agnusmail.modules.identity.models import User
from agnusmail.modules.keys.models import PublicKey, PublicKeyStatus

OPEN_STATUSES = (DeviceStatus.PENDING, DeviceStatus.ACTIVE)


class AttestationRejectedError(AgnusmailError):
    status_code = 422
    message = "wallet attestation rejected"
    code = "ATTESTATION_REJECTED"


@dataclass(frozen=True)
class DevicePolicy:
    max_devices_per_user: int


def get_owned_device(
    session: Session, owner_id: uuid.UUID, device_id: uuid.UUID, *, lock: bool = False
) -> Device:
    """The device if it belongs to ``owner_id``; otherwise 404 (never 403)."""
    query = select(Device).where(Device.id == device_id, Device.user_id == owner_id)
    if lock:
        query = query.with_for_update()
    device = session.scalars(query).one_or_none()
    if device is None:
        raise ResourceNotFoundError("device not found")
    return device


def register_device(
    session: Session, actor: ActorContext, name: str, policy: DevicePolicy
) -> Device:
    # Serialize registrations of the same user so the limit cannot be raced past.
    session.execute(select(User.id).where(User.id == actor.user_id).with_for_update())
    open_devices = session.scalar(
        select(func.count())
        .select_from(Device)
        .where(Device.user_id == actor.user_id, Device.status.in_(OPEN_STATUSES))
    )
    if int(open_devices or 0) >= policy.max_devices_per_user:
        raise LimitExceededError("device limit reached; revoke a device first")
    device = Device(user_id=actor.user_id, name=name, status=DeviceStatus.PENDING)
    session.add(device)
    session.flush()
    record_event(
        session,
        actor,
        AuditEventType.DEVICE_REGISTERED,
        owner_id=actor.user_id,
        device_id=device.id,
        details={"status": DeviceStatus.PENDING.value},
    )
    return device


def list_devices(
    session: Session,
    owner_id: uuid.UUID,
    *,
    status: DeviceStatus | None,
    limit: int,
    offset: int,
) -> tuple[list[Device], int]:
    conditions = [Device.user_id == owner_id]
    if status is not None:
        conditions.append(Device.status == status)
    total = session.scalar(select(func.count()).select_from(Device).where(*conditions))
    rows = session.scalars(
        select(Device)
        .where(*conditions)
        .order_by(Device.created_at.desc(), Device.id.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return list(rows), int(total or 0)


@dataclass(frozen=True)
class WalletContext:
    """Where attestations are valid: the instance (``service``) and the SIWE chain."""

    service: str
    chain_id: int


@dataclass(frozen=True)
class CertificateInput:
    issued_at: int
    expires_at: int
    signature: str  # "0x" + 130 hex


@dataclass(frozen=True)
class RevocationInput:
    revoked_at: int
    signature: str


def _account(session: Session, user_id: uuid.UUID) -> str:
    return session.scalars(select(User.ethereum_address).where(User.id == user_id)).one()


def _signature_bytes(signature: str) -> bytes:
    return bytes.fromhex(signature.removeprefix("0x"))


def authorize_device(
    session: Session,
    actor: ActorContext,
    device_id: uuid.UUID,
    certificate: CertificateInput,
    wallet: WalletContext,
    now: datetime,
) -> Device:
    """Trust the device with a wallet-signed DeviceCertificate (4.D.4), or renew it.

    The certificate binds the v6 fingerprint fixed by the device's first OpenPGP
    certificate, so the device must have registered one. Renewal (active device) needs
    a strictly newer ``issuedAt``.
    """
    device = get_owned_device(session, actor.user_id, device_id, lock=True)
    if device.status == DeviceStatus.REVOKED:
        raise InvalidStateError("device is revoked")
    if device.fingerprint is None:
        raise InvalidStateError("register the device's OpenPGP certificate first")
    claim = DeviceCertificateClaim(
        account=_account(session, actor.user_id),
        device_fingerprint=device.fingerprint,
        service=wallet.service,
        issued_at=certificate.issued_at,
        expires_at=certificate.expires_at,
    )
    try:
        verify_device_certificate(
            claim, _signature_bytes(certificate.signature), chain_id=wallet.chain_id, now=now
        )
    except AttestationError as exc:
        raise AttestationRejectedError(f"device certificate rejected: {exc.reason}") from exc
    issued_at = datetime.fromtimestamp(certificate.issued_at, tz=UTC)
    expires_at = datetime.fromtimestamp(certificate.expires_at, tz=UTC)
    renewal = device.status == DeviceStatus.ACTIVE
    if renewal and device.certificate_issued_at is not None:
        current = device.certificate_issued_at
        current = current.replace(tzinfo=UTC) if current.tzinfo is None else current
        if issued_at <= current:
            raise InvalidStateError("a renewal needs a newer certificate")
    device.certificate_signature = certificate.signature.lower()
    device.certificate_issued_at = issued_at
    device.certificate_expires_at = expires_at
    if not renewal:
        device.status = DeviceStatus.ACTIVE
        device.authorized_at = now
    session.flush()
    details: dict[str, object] = {
        "fingerprint": device.fingerprint,
        "certificate_expires_at": expires_at.isoformat(),
    }
    if not renewal:
        details |= {"from": DeviceStatus.PENDING.value, "to": DeviceStatus.ACTIVE.value}
    record_event(
        session,
        actor,
        AuditEventType.DEVICE_CERTIFICATE_RENEWED if renewal else AuditEventType.DEVICE_AUTHORIZED,
        owner_id=actor.user_id,
        device_id=device.id,
        details=details,
    )
    return device


def revoke_device(
    session: Session,
    actor: ActorContext,
    device_id: uuid.UUID,
    reason: str | None,
    now: datetime,
    *,
    wallet_revocation: RevocationInput | None = None,
    wallet: WalletContext | None = None,
) -> Device:
    """Revoke the device and every non-revoked key it holds (terminal).

    An optional wallet-signed DeviceRevocation is verified and kept so senders who cached
    the device certificate can see the revocation without trusting the server.
    """
    device = get_owned_device(session, actor.user_id, device_id, lock=True)
    if device.status == DeviceStatus.REVOKED:
        raise InvalidStateError("device is already revoked")
    if wallet_revocation is not None:
        if wallet is None or device.fingerprint is None:
            raise InvalidStateError("this device has no certificate to revoke by wallet")
        claim = DeviceRevocationClaim(
            account=_account(session, actor.user_id),
            device_fingerprint=device.fingerprint,
            service=wallet.service,
            revoked_at=wallet_revocation.revoked_at,
        )
        try:
            verify_device_revocation(
                claim,
                _signature_bytes(wallet_revocation.signature),
                chain_id=wallet.chain_id,
                now=now,
            )
        except AttestationError as exc:
            raise AttestationRejectedError(f"device revocation rejected: {exc.reason}") from exc
        device.wallet_revocation_signature = wallet_revocation.signature.lower()
        device.wallet_revoked_at = datetime.fromtimestamp(wallet_revocation.revoked_at, tz=UTC)
    previous = device.status
    device.status = DeviceStatus.REVOKED
    device.revoked_at = now
    device.revocation_reason = reason
    keys = session.scalars(
        select(PublicKey)
        .where(PublicKey.device_id == device.id, PublicKey.status != PublicKeyStatus.REVOKED)
        .order_by(PublicKey.version)
        .with_for_update()
    ).all()
    for key in keys:
        key_previous = key.status
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
            details={
                "from": key_previous,
                "version": key.version,
                "format": key.format,
                "material_digest": key.material_digest,
                "cause": "device_revoked",
            },
        )
    session.flush()
    record_event(
        session,
        actor,
        AuditEventType.DEVICE_REVOKED,
        owner_id=actor.user_id,
        device_id=device.id,
        details={
            "from": str(previous),
            "to": DeviceStatus.REVOKED.value,
            "reason": reason,
            "keys_revoked": len(keys),
            "wallet_signed": wallet_revocation is not None,
        },
    )
    return device
