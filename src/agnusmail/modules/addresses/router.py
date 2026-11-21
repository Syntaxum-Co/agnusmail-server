"""Addresses: claim and list your own (/v1/addresses), resolve any (/v1/directory)."""

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Path, Request
from sqlalchemy.orm import Session

from agnusmail.core.config import Settings
from agnusmail.infrastructure.database.transaction import run_in_transaction
from agnusmail.modules.addresses import service
from agnusmail.modules.addresses.models import AddressKind
from agnusmail.modules.addresses.schemas import (
    AddressClaim,
    AddressList,
    AddressOut,
    ResolvedAddress,
)
from agnusmail.modules.authentication.dependencies import (
    CurrentSession,
    DbSessionFactory,
    RecentSession,
    actor_context,
)

router = APIRouter(tags=["addresses"])

Email = Annotated[str, Path(min_length=3, max_length=320)]


@router.post("/addresses", status_code=201)
async def claim_address(
    request: Request, payload: AddressClaim, session: RecentSession, db: DbSessionFactory
) -> AddressOut:
    """Claim the account's permanent address (step-up: recent SIWE login required)."""
    settings: Settings = request.app.state.settings
    actor = actor_context(request, session)
    return await run_in_transaction(
        db,
        lambda s: AddressOut.from_address(
            service.claim_address(s, actor, payload.local_part, settings.mail_domain)
        ),
    )


@router.post("/addresses/aliases", status_code=201)
async def claim_alias(
    request: Request, payload: AddressClaim, session: RecentSession, db: DbSessionFactory
) -> AddressOut:
    """Add an alias: same name rules, at most 5, never given to anyone else
    (step-up: recent SIWE login required)."""
    settings: Settings = request.app.state.settings
    actor = actor_context(request, session)

    def work(s: Session) -> AddressOut:
        request.app.state.quota_policy.require_active(s, actor.user_id, datetime.now(UTC))
        return AddressOut.from_address(
            service.claim_address(
                s, actor, payload.local_part, settings.mail_domain, AddressKind.ALIAS
            )
        )

    return await run_in_transaction(db, work)


@router.post("/addresses/{address_id}/disable")
async def disable_alias(
    request: Request, address_id: uuid.UUID, session: CurrentSession, db: DbSessionFactory
) -> AddressOut:
    actor = actor_context(request, session)
    return await run_in_transaction(
        db,
        lambda s: AddressOut.from_address(service.set_alias_enabled(s, actor, address_id, False)),
    )


@router.post("/addresses/{address_id}/enable")
async def enable_alias(
    request: Request, address_id: uuid.UUID, session: RecentSession, db: DbSessionFactory
) -> AddressOut:
    actor = actor_context(request, session)
    return await run_in_transaction(
        db,
        lambda s: AddressOut.from_address(service.set_alias_enabled(s, actor, address_id, True)),
    )


@router.get("/addresses")
async def list_addresses(session: CurrentSession, db: DbSessionFactory) -> AddressList:
    owner = uuid.UUID(session.user_id)
    return await run_in_transaction(
        db,
        lambda s: AddressList(
            items=[AddressOut.from_address(a) for a in service.list_addresses(s, owner)]
        ),
    )


@router.get("/directory/addresses/{email}")
async def resolve_address(
    request: Request, email: Email, session: CurrentSession, db: DbSessionFactory
) -> ResolvedAddress:
    """Resolve an address to its account (404 if unknown). Authenticated and rate
    limited per user; existence is revealed, as SMTP RCPT does."""
    settings: Settings = request.app.state.settings

    def work(s: Session) -> ResolvedAddress:
        address, user = service.resolve(s, email, settings.mail_domain)
        return ResolvedAddress(email=address.email, account=user.ethereum_address)

    return await run_in_transaction(db, work)
