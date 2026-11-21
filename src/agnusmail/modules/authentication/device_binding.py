"""Binding a session to a device (protocol v1 §5, 4.D.5).

1. ``POST /v1/auth/device/challenge`` — 32 random bytes, tied to the session, single use,
   valid for 120 s; the response carries the exact statement to sign.
2. ``POST /v1/auth/device/bind`` — a v6 binary detached signature by the device's signing
   subkey over ``agnusmail/device-session/v1\\n{service}\\n{fingerprint}\\n{challenge}``.
   If it verifies against the device's active certificate, the session records the
   device and is indexed by it.
3. Revoking a device revokes its sessions. ``DeviceSession`` (for message, attachment
   and recovery routes) also re-checks in the database, on every request, that the
   bound device is still active.
"""

import base64
import binascii
import uuid
from dataclasses import dataclass
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.core.config import Settings
from agnusmail.core.exceptions import (
    AgnusmailError,
    InvalidStateError,
    ResourceNotFoundError,
    SessionRevokedError,
)
from agnusmail.core.logging import get_logger
from agnusmail.infrastructure.database.transaction import run_in_transaction, run_sync_transaction
from agnusmail.infrastructure.openpgp import SignatureInvalidError, verify_detached
from agnusmail.modules.audit.models import AuditEventType
from agnusmail.modules.audit.service import record_event
from agnusmail.modules.authentication.dependencies import (
    CurrentSession,
    DbSessionFactory,
    SessionContext,
    actor_context,
)
from agnusmail.modules.authentication.stores import (
    DEVICE_CHALLENGE_TTL_SECONDS,
    DeviceChallengeStore,
    SessionStore,
)
from agnusmail.modules.devices.models import Device, DeviceStatus
from agnusmail.modules.keys.models import PublicKey, PublicKeyStatus

log = get_logger(__name__)

router = APIRouter(prefix="/auth/device", tags=["auth"])

SESSION_DOMAIN = "agnusmail/device-session/v1"
MAX_SIGNATURE_BYTES = 1024


class DeviceSessionRequiredError(AgnusmailError):
    status_code = 403
    message = "this action needs a session bound to an active device"
    code = "DEVICE_SESSION_REQUIRED"


class DeviceProofRejectedError(AgnusmailError):
    status_code = 401
    message = "device proof rejected"
    code = "DEVICE_PROOF_REJECTED"


def session_statement(service: str, fingerprint: str, challenge: str) -> bytes:
    return f"{SESSION_DOMAIN}\n{service}\n{fingerprint}\n{challenge}".encode("ascii")


def _decode_signature(value: object) -> bytes:
    if not isinstance(value, str):
        raise ValueError("must be a base64 string")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("invalid base64") from exc
    if not 0 < len(decoded) <= MAX_SIGNATURE_BYTES:
        raise ValueError(f"signature must be 1..{MAX_SIGNATURE_BYTES} bytes")
    return decoded


class ChallengeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    device_id: uuid.UUID = Field(strict=False)  # JSON string -> UUID


class ChallengeOut(BaseModel):
    challenge: str
    statement: str  # exactly what the signing subkey must sign (UTF-8/ASCII)
    expires_in: int


class BindRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    device_id: uuid.UUID = Field(strict=False)
    signature: Annotated[bytes, BeforeValidator(_decode_signature)]


class BoundDeviceOut(BaseModel):
    device_id: uuid.UUID
    fingerprint: str


def _active_device(session: Session, owner: uuid.UUID, device_id: uuid.UUID) -> Device:
    device = session.scalars(
        select(Device).where(Device.id == device_id, Device.user_id == owner)
    ).one_or_none()
    if device is None:
        raise ResourceNotFoundError("device not found")
    if device.status != DeviceStatus.ACTIVE or device.fingerprint is None:
        raise InvalidStateError("only an active device can be bound to a session")
    return device


def _active_key(session: Session, device: Device) -> PublicKey:
    key = session.scalars(
        select(PublicKey)
        .where(PublicKey.device_id == device.id, PublicKey.status == PublicKeyStatus.ACTIVE)
        .order_by(PublicKey.version.desc())
        .limit(1)
    ).one_or_none()
    if key is None:
        raise InvalidStateError("the device has no active certificate")
    return key


def _stores(request: Request) -> tuple[SessionStore, DeviceChallengeStore]:
    return request.app.state.session_store, request.app.state.device_challenge_store


@router.post("/challenge")
async def create_challenge(
    request: Request, payload: ChallengeRequest, session: CurrentSession, db: DbSessionFactory
) -> ChallengeOut:
    settings: Settings = request.app.state.settings
    owner = uuid.UUID(session.user_id)
    device = await run_in_transaction(db, lambda s: _active_device(s, owner, payload.device_id))
    session_store, challenges = _stores(request)
    challenge = await challenges.create(session_store.digest(session.token), str(device.id))
    statement = session_statement(settings.siwe_domain, str(device.fingerprint), challenge)
    return ChallengeOut(
        challenge=challenge,
        statement=statement.decode("ascii"),
        expires_in=DEVICE_CHALLENGE_TTL_SECONDS,
    )


@router.post("/bind")
async def bind_device(
    request: Request, payload: BindRequest, session: CurrentSession, db: DbSessionFactory
) -> BoundDeviceOut:
    settings: Settings = request.app.state.settings
    session_store, challenges = _stores(request)
    pending = await challenges.consume(session_store.digest(session.token))
    if pending is None or pending["device_id"] != str(payload.device_id):
        raise DeviceProofRejectedError("no pending challenge for this device")
    owner = uuid.UUID(session.user_id)
    actor = actor_context(request, session)

    def verify_and_audit(s: Session) -> BoundDeviceOut:
        device = _active_device(s, owner, payload.device_id)
        key = _active_key(s, device)
        statement = session_statement(
            settings.siwe_domain, str(device.fingerprint), pending["challenge"]
        )
        try:
            signer = verify_detached(key.material, statement, payload.signature)
        except SignatureInvalidError as exc:
            raise DeviceProofRejectedError("device signature does not verify") from exc
        if signer != key.signing_fingerprint:
            raise DeviceProofRejectedError("the signature must come from the signing subkey")
        record_event(
            s,
            actor,
            AuditEventType.AUTH_SESSION_BOUND,
            owner_id=owner,
            device_id=device.id,
            details={"session": session.record.data.get("session_id")},
        )
        return BoundDeviceOut(device_id=device.id, fingerprint=str(device.fingerprint))

    bound = await run_in_transaction(db, verify_and_audit)
    if not await session_store.bind_device(session.token, str(bound.device_id)):
        raise SessionRevokedError()
    return bound


@dataclass(frozen=True)
class DeviceSessionContext:
    session: SessionContext
    device_id: uuid.UUID
    fingerprint: str


def _bound_device(
    factory: sessionmaker[Session] | None, owner: uuid.UUID, device_id: uuid.UUID
) -> Device | None:
    def work(s: Session) -> Device | None:
        return s.scalars(
            select(Device).where(
                Device.id == device_id,
                Device.user_id == owner,
                Device.status == DeviceStatus.ACTIVE,
            )
        ).one_or_none()

    return run_sync_transaction(factory, work)


async def device_session(request: Request, session: CurrentSession) -> DeviceSessionContext:
    """A session bound to a device that is STILL active (checked on every request)."""
    raw_device_id = session.record.data.get("device_id")
    if not raw_device_id:
        raise DeviceSessionRequiredError()
    device_id = uuid.UUID(str(raw_device_id))
    owner = uuid.UUID(session.user_id)
    device = await run_in_threadpool(
        _bound_device, request.app.state.db_session_factory, owner, device_id
    )
    if device is None:  # revoked meanwhile (or index revocation failed): end the session
        session_store: SessionStore = request.app.state.session_store
        await session_store.revoke(session.token)
        raise SessionRevokedError()
    return DeviceSessionContext(session, device_id, str(device.fingerprint))


DeviceSession = Annotated[DeviceSessionContext, Depends(device_session)]


@router.get("")
async def current_device(session: DeviceSession) -> BoundDeviceOut:
    """The device bound to the caller's session (403 if none)."""
    return BoundDeviceOut(device_id=session.device_id, fingerprint=session.fingerprint)


async def revoke_sessions_of(request: Request, device_id: uuid.UUID) -> None:
    """After a device is revoked: end its sessions. Failures are logged; ``DeviceSession``
    still refuses them because the device is no longer active."""
    session_store: SessionStore = request.app.state.session_store
    try:
        revoked = await session_store.revoke_device_sessions(str(device_id))
    except Exception as exc:  # Redis down: the per-request database check still applies
        log.error("device_sessions_revoke_failed", error_type=type(exc).__name__)
        return
    if revoked:
        log.info("device_sessions_revoked", device_id=str(device_id), count=revoked)
