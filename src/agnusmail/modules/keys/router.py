"""Public key endpoints.

- /v1/devices/{device_id}/keys...: the owner manages the keys of their devices.
- /v1/keys/{address}: directory lookup (authenticated users only, rate limited per user).
"""

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Path, Query, Request
from sqlalchemy.orm import Session

from agnusmail.core.config import Settings
from agnusmail.infrastructure.database.transaction import run_in_transaction
from agnusmail.modules.authentication.dependencies import (
    CurrentSession,
    DbSessionFactory,
    actor_context,
    is_recently_authenticated,
)
from agnusmail.modules.identity.repository import normalize_address
from agnusmail.modules.keys import service
from agnusmail.modules.keys.policy import KeyMaterialPolicy, RegistrationContext
from agnusmail.modules.keys.schemas import (
    DirectoryKeyOut,
    DirectoryOut,
    PublicKeyCreate,
    PublicKeyOut,
    PublicKeyPage,
    WalletRevocationOut,
)
from agnusmail.modules.recovery.router import RecoveryKeyOut, migration_evidence

router = APIRouter(tags=["keys"])

Limit = Annotated[int, Query(ge=1, le=100)]
Offset = Annotated[int, Query(ge=0, le=10_000)]
Address = Annotated[str, Path(pattern=r"^0x[0-9a-fA-F]{40}$")]


@router.post("/devices/{device_id}/keys", status_code=201)
async def register_key(
    request: Request,
    device_id: uuid.UUID,
    payload: PublicKeyCreate,
    session: CurrentSession,
    db: DbSessionFactory,
) -> PublicKeyOut:
    """Publish a new version of the device's OpenPGP v6 certificate with its proof of
    possession (protocol v1 §3). Active devices also require a recent login (step-up)."""
    settings: Settings = request.app.state.settings
    policy: KeyMaterialPolicy = request.app.state.key_policy
    actor = actor_context(request, session)
    recent = is_recently_authenticated(request, session)
    limits = service.KeyLimits(max_keys_per_device=settings.max_keys_per_device)
    context = RegistrationContext(
        service=settings.siwe_domain,
        account=str(session.record.data["address"]),
        now=datetime.now(UTC),
    )

    def work(s: Session) -> PublicKeyOut:
        key = service.register_key(
            s,
            actor,
            device_id,
            payload.format,
            payload.material,
            payload.proof,
            policy=policy,
            context=context,
            limits=limits,
            recently_authenticated=recent,
        )
        return PublicKeyOut.from_key(key)

    return await run_in_transaction(db, work)


@router.get("/devices/{device_id}/keys")
async def list_device_keys(
    device_id: uuid.UUID,
    session: CurrentSession,
    db: DbSessionFactory,
    limit: Limit = 25,
    offset: Offset = 0,
) -> PublicKeyPage:
    owner = uuid.UUID(session.user_id)

    def work(s: Session) -> PublicKeyPage:
        keys, total = service.list_device_keys(s, owner, device_id, limit=limit, offset=offset)
        return PublicKeyPage(
            items=[PublicKeyOut.from_key(k) for k in keys], total=total, limit=limit, offset=offset
        )

    return await run_in_transaction(db, work)


@router.post("/devices/{device_id}/keys/{key_id}/revoke")
async def revoke_key(
    request: Request,
    device_id: uuid.UUID,
    key_id: uuid.UUID,
    session: CurrentSession,
    db: DbSessionFactory,
) -> PublicKeyOut:
    actor = actor_context(request, session)
    now = datetime.now(UTC)
    return await run_in_transaction(
        db, lambda s: PublicKeyOut.from_key(service.revoke_key(s, actor, device_id, key_id, now))
    )


@router.get("/keys/{address}")
async def lookup_directory(
    request: Request, address: Address, session: CurrentSession, db: DbSessionFactory
) -> DirectoryOut:
    """Published keys of an address, each with its wallet-signed device certificate, plus
    wallet-signed revocations. Unknown addresses return an empty list (no account
    enumeration). Senders verify the certificates themselves (protocol v1 §4.3)."""
    settings: Settings = request.app.state.settings
    normalized = normalize_address(address)
    return await run_in_transaction(
        db, lambda s: build_directory(s, settings, normalized, datetime.now(UTC))
    )


def build_directory(s: Session, settings: Settings, address: str, now: datetime) -> DirectoryOut:
    """The directory entry of a (normalized) wallet address; also served by the secure
    portal for the sender of a portal message (spec §11)."""
    view = service.lookup_directory(s, address, now)
    return DirectoryOut(
        address=address,
        service=settings.siwe_domain,
        chain_id=settings.siwe_chain_id,
        keys=[DirectoryKeyOut.from_entry(key, device) for key, device in view.entries],
        revocations=[WalletRevocationOut.from_device(d) for d in view.wallet_revocations],
        recovery_key=(
            None
            if view.recovery_key is None
            else RecoveryKeyOut.from_key(view.recovery_key).model_dump(mode="json")
        ),
        migrations=[migration_evidence(m) for m in view.migrations],
    )
