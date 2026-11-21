"""Device endpoints (/v1/devices). Every route requires a session and is scoped to it."""

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Query, Request
from sqlalchemy.orm import Session

from agnusmail.core.config import Settings
from agnusmail.infrastructure.database.transaction import run_in_transaction
from agnusmail.modules.audit.schemas import AuditEventOut, AuditEventPage
from agnusmail.modules.audit.service import list_events
from agnusmail.modules.authentication.dependencies import (
    CurrentSession,
    DbSessionFactory,
    actor_context,
)
from agnusmail.modules.authentication.device_binding import revoke_sessions_of
from agnusmail.modules.devices import service
from agnusmail.modules.devices.models import DeviceStatus
from agnusmail.modules.devices.schemas import (
    DeviceCreate,
    DeviceOut,
    DevicePage,
    DeviceRevoke,
    WalletSignedCertificate,
)

router = APIRouter(prefix="/devices", tags=["devices"])

Limit = Annotated[int, Query(ge=1, le=100)]
Offset = Annotated[int, Query(ge=0, le=10_000)]


def _owner(session: CurrentSession) -> uuid.UUID:
    return uuid.UUID(session.user_id)


@router.post("", status_code=201)
async def register_device(
    request: Request, payload: DeviceCreate, session: CurrentSession, db: DbSessionFactory
) -> DeviceOut:
    """Register a new device in the ``pending`` state (not trusted until authorized)."""
    settings: Settings = request.app.state.settings
    actor = actor_context(request, session)
    from agnusmail.modules.abuse import limits

    await limits.consume(  # registering and revoking cannot churn devices forever
        request,
        "device_registrations",
        session.user_id,
        1,
        settings.device_registrations_per_day,
        limits.DAY,
    )
    policy = service.DevicePolicy(max_devices_per_user=settings.max_devices_per_user)
    return await run_in_transaction(
        db,
        lambda s: DeviceOut.model_validate(service.register_device(s, actor, payload.name, policy)),
    )


@router.get("")
async def list_devices(
    session: CurrentSession,
    db: DbSessionFactory,
    status: DeviceStatus | None = None,
    limit: Limit = 25,
    offset: Offset = 0,
) -> DevicePage:
    owner = _owner(session)

    def work(s: Session) -> DevicePage:
        devices, total = service.list_devices(
            s,
            owner,
            status=status,
            limit=limit,
            offset=offset,
        )
        return DevicePage(
            items=[DeviceOut.model_validate(d) for d in devices],
            total=total,
            limit=limit,
            offset=offset,
        )

    return await run_in_transaction(db, work)


@router.get("/{device_id}")
async def get_device(
    device_id: uuid.UUID, session: CurrentSession, db: DbSessionFactory
) -> DeviceOut:
    owner = _owner(session)
    return await run_in_transaction(
        db, lambda s: DeviceOut.model_validate(service.get_owned_device(s, owner, device_id))
    )


def _wallet(request: Request) -> service.WalletContext:
    settings: Settings = request.app.state.settings
    return service.WalletContext(service=settings.siwe_domain, chain_id=settings.siwe_chain_id)


@router.post("/{device_id}/authorize")
async def authorize_device(
    request: Request,
    device_id: uuid.UUID,
    payload: WalletSignedCertificate,
    session: CurrentSession,
    db: DbSessionFactory,
) -> DeviceOut:
    """Trust a device (or renew its certificate) with an EIP-712 DeviceCertificate signed
    by the account's wallet over the device's v6 fingerprint (protocol v1 §4). The
    wallet signature replaces the interim step-up."""
    actor = actor_context(request, session)
    wallet = _wallet(request)
    certificate = service.CertificateInput(
        issued_at=payload.issued_at, expires_at=payload.expires_at, signature=payload.signature
    )
    now = datetime.now(UTC)
    return await run_in_transaction(
        db,
        lambda s: DeviceOut.model_validate(
            service.authorize_device(s, actor, device_id, certificate, wallet, now)
        ),
    )


@router.post("/{device_id}/revoke")
async def revoke_device(
    request: Request,
    device_id: uuid.UUID,
    payload: DeviceRevoke,
    session: CurrentSession,
    db: DbSessionFactory,
) -> DeviceOut:
    """Revoke a device (terminal) and every key it holds; optionally with a wallet-signed
    EIP-712 DeviceRevocation that senders can verify themselves."""
    actor = actor_context(request, session)
    now = datetime.now(UTC)
    revocation = (
        None
        if payload.wallet_revocation is None
        else service.RevocationInput(
            revoked_at=payload.wallet_revocation.revoked_at,
            signature=payload.wallet_revocation.signature,
        )
    )
    wallet = _wallet(request)
    revoked = await run_in_transaction(
        db,
        lambda s: DeviceOut.model_validate(
            service.revoke_device(
                s,
                actor,
                device_id,
                payload.reason,
                now,
                wallet_revocation=revocation,
                wallet=wallet,
            )
        ),
    )
    await revoke_sessions_of(request, device_id)  # sessions bound to it end now
    return revoked


@router.get("/{device_id}/events")
async def device_history(
    device_id: uuid.UUID,
    session: CurrentSession,
    db: DbSessionFactory,
    limit: Limit = 25,
    offset: Offset = 0,
) -> AuditEventPage:
    """Audit history of the device and its keys, newest first."""
    owner = _owner(session)

    def work(s: Session) -> AuditEventPage:
        service.get_owned_device(s, owner, device_id)  # 404 if foreign
        events, total = list_events(
            s,
            owner,
            device_id=device_id,
            limit=limit,
            offset=offset,
        )
        return AuditEventPage(
            items=[AuditEventOut.from_event(e) for e in events],
            total=total,
            limit=limit,
            offset=offset,
        )

    return await run_in_transaction(db, work)
