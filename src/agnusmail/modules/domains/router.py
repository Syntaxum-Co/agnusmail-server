"""Custom domains API (/v1/domains).

Adding, verifying and removing a domain and creating its addresses change where mail
is delivered: they need a recent login (step-up), like claiming an address.
"""

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from agnusmail.core.config import Settings
from agnusmail.core.schemas import UtcDatetime
from agnusmail.infrastructure.database.transaction import run_in_transaction
from agnusmail.modules.addresses.schemas import AddressClaim, AddressOut
from agnusmail.modules.authentication.dependencies import (
    CurrentSession,
    DbSessionFactory,
    RecentSession,
    actor_context,
)
from agnusmail.modules.domains import service
from agnusmail.modules.domains.dns import TxtLookup, lookup_txt
from agnusmail.modules.domains.models import MailDomain

router = APIRouter(prefix="/domains", tags=["domains"])


class DomainIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    name: str = Field(min_length=4, max_length=253)


class RecordOut(BaseModel):
    type: str
    host: str
    value: str
    purpose: str


class DomainOut(BaseModel):
    id: uuid.UUID
    name: str
    status: str
    records: list[RecordOut]  # what to publish; only the verification TXT is checked
    created_at: UtcDatetime
    verified_at: UtcDatetime | None


class DomainList(BaseModel):
    items: list[DomainOut]


def _out(domain: MailDomain, settings: Settings) -> DomainOut:
    published = service.records(
        domain,
        mail_domain=settings.mail_domain,
        mx_host=settings.inbound_smtp_hostname or settings.mail_domain,
        selector=settings.outbound_dkim_selector,
    )
    return DomainOut(
        id=domain.id,
        name=domain.name,
        status=domain.status,
        records=[RecordOut(**vars(r)) for r in published],
        created_at=domain.created_at,
        verified_at=domain.verified_at,
    )


@router.post("", status_code=201)
async def add_domain(
    request: Request, payload: DomainIn, session: RecentSession, db: DbSessionFactory
) -> DomainOut:
    settings: Settings = request.app.state.settings
    actor = actor_context(request, session)

    def work(s: Session) -> DomainOut:
        request.app.state.quota_policy.require_active(s, actor.user_id, datetime.now(UTC))
        return _out(service.add(s, actor, payload.name, settings.mail_domain), settings)

    return await run_in_transaction(db, work)


@router.get("")
async def list_domains(
    request: Request, session: CurrentSession, db: DbSessionFactory
) -> DomainList:
    settings: Settings = request.app.state.settings
    owner = uuid.UUID(session.user_id)
    return await run_in_transaction(
        db,
        lambda s: DomainList(items=[_out(d, settings) for d in service.list_domains(s, owner)]),
    )


@router.post("/{domain_id}/verify")
async def verify_domain(
    request: Request, domain_id: uuid.UUID, session: RecentSession, db: DbSessionFactory
) -> DomainOut:
    settings: Settings = request.app.state.settings
    actor = actor_context(request, session)
    host = await run_in_transaction(
        db, lambda s: service.own_domain(s, actor.user_id, domain_id).verification_host
    )
    lookup: TxtLookup = getattr(request.app.state, "dns_txt", None) or lookup_txt
    values = await run_in_threadpool(lookup, host)  # outside any transaction
    now = datetime.now(UTC)

    def work(s: Session) -> DomainOut:
        return _out(service.verify(s, actor, domain_id, values, now), settings)

    return await run_in_transaction(db, work)


@router.delete("/{domain_id}", status_code=204)
async def remove_domain(
    request: Request, domain_id: uuid.UUID, session: RecentSession, db: DbSessionFactory
) -> None:
    actor = actor_context(request, session)
    await run_in_transaction(db, lambda s: service.remove(s, actor, domain_id))


@router.post("/{domain_id}/addresses", status_code=201)
async def add_domain_address(
    request: Request,
    domain_id: uuid.UUID,
    payload: AddressClaim,
    session: RecentSession,
    db: DbSessionFactory,
) -> AddressOut:
    actor = actor_context(request, session)

    def work(s: Session) -> AddressOut:
        request.app.state.quota_policy.require_active(s, actor.user_id, datetime.now(UTC))
        return AddressOut.from_address(service.add_address(s, actor, domain_id, payload.local_part))

    return await run_in_transaction(db, work)
