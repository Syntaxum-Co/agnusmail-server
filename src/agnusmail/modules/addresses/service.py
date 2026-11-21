"""Claiming and resolving addresses."""

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from agnusmail.core.exceptions import (
    AgnusmailError,
    InvalidStateError,
    ResourceNotFoundError,
)
from agnusmail.modules.addresses import rules
from agnusmail.modules.addresses.models import (
    MAX_ALIASES,
    AddressKind,
    AddressStatus,
    MailAddress,
)
from agnusmail.modules.audit.models import AuditEventType
from agnusmail.modules.audit.service import ActorContext, record_event
from agnusmail.modules.identity.models import User, UserStatus


class AddressInvalidError(AgnusmailError):
    status_code = 422
    message = "invalid address name"
    code = "ADDRESS_INVALID"


class AddressReservedError(AgnusmailError):
    status_code = 409
    message = "this name is reserved"
    code = "ADDRESS_RESERVED"


class AddressTakenError(AgnusmailError):
    status_code = 409
    message = "this name, or one too similar to it, is already taken"
    code = "ADDRESS_TAKEN"


class AddressLimitError(AgnusmailError):
    status_code = 409
    message = "the account already has an address"
    code = "ADDRESS_LIMIT"


class PrimaryAddressRequiredError(AgnusmailError):
    status_code = 409
    message = "claim the account's address before adding aliases"
    code = "PRIMARY_ADDRESS_REQUIRED"


def claim_address(
    session: Session,
    actor: ActorContext,
    requested: str,
    domain: str,
    kind: AddressKind = AddressKind.PRIMARY,
) -> MailAddress:
    """Claim the account's permanent address (or one of its aliases) and audit it, in
    the caller's transaction."""
    try:
        local_part = rules.normalize(requested)
        rules.check_not_reserved(local_part)
    except rules.ReservedLocalPartError as exc:
        raise AddressReservedError() from exc
    except rules.InvalidLocalPartError as exc:
        raise AddressInvalidError(str(exc)) from exc
    # Serialize claims of the same account (one primary, at most MAX_ALIASES aliases).
    session.execute(select(User.id).where(User.id == actor.user_id).with_for_update())
    kinds = list(
        session.scalars(select(MailAddress.kind).where(MailAddress.user_id == actor.user_id))
    )
    if kind is AddressKind.PRIMARY and AddressKind.PRIMARY in kinds:
        raise AddressLimitError()
    if kind is AddressKind.ALIAS:
        if AddressKind.PRIMARY not in kinds:
            raise PrimaryAddressRequiredError()
        if kinds.count(AddressKind.ALIAS) >= MAX_ALIASES:
            raise AddressLimitError(f"at most {MAX_ALIASES} aliases per account")
    canonical = rules.canonical(local_part)
    taken = session.scalar(
        select(MailAddress.id).where(
            MailAddress.domain == domain, MailAddress.canonical == canonical
        )
    )
    if taken:
        raise AddressTakenError()
    # A concurrent claim of the same canonical form loses on the unique index (409).
    address = MailAddress(
        user_id=actor.user_id,
        local_part=local_part,
        canonical=canonical,
        domain=domain,
        status=AddressStatus.ACTIVE,
        kind=kind,
    )
    session.add(address)
    session.flush()
    record_event(
        session,
        actor,
        AuditEventType.ADDRESS_CLAIMED
        if kind is AddressKind.PRIMARY
        else AuditEventType.ADDRESS_ALIAS_CLAIMED,
        owner_id=actor.user_id,
        details={"address": address.email},
    )
    return address


def set_alias_enabled(
    session: Session, actor: ActorContext, address_id: uuid.UUID, enabled: bool
) -> MailAddress:
    """Switch an alias on or off. Off: it stops resolving (inbound mail is refused as an
    unknown user) and cannot be used as From; the name stays with this account."""
    address = session.get(MailAddress, address_id)
    if address is None or address.user_id != actor.user_id:
        raise ResourceNotFoundError()
    if address.kind == AddressKind.PRIMARY or address.status == AddressStatus.RETIRED:
        raise InvalidStateError("only aliases and domain addresses can be enabled or disabled")
    wanted = AddressStatus.ACTIVE if enabled else AddressStatus.DISABLED
    if address.status != wanted:
        address.status = wanted
        session.flush()
        record_event(
            session,
            actor,
            AuditEventType.ADDRESS_ENABLED if enabled else AuditEventType.ADDRESS_DISABLED,
            owner_id=actor.user_id,
            details={"address": address.email},
        )
    return address


def active_addresses(session: Session, owner_id: uuid.UUID) -> list[MailAddress]:
    """Addresses the account may send from (primary first)."""
    rows = session.scalars(
        select(MailAddress)
        .where(MailAddress.user_id == owner_id, MailAddress.status == AddressStatus.ACTIVE)
        .order_by((MailAddress.kind == AddressKind.PRIMARY).desc(), MailAddress.created_at)
    )
    return list(rows)


def list_addresses(session: Session, owner_id: uuid.UUID) -> list[MailAddress]:
    rows = session.scalars(
        select(MailAddress).where(MailAddress.user_id == owner_id).order_by(MailAddress.created_at)
    )
    return list(rows)


def resolve(session: Session, email: str, domain: str) -> tuple[MailAddress, User]:
    """Exact-match routing (no canonical folding). Anything unusable → 404.

    ``domain`` is the service's domain; addresses on a verified custom domain
    resolve too, only while the domain is verified by the address's owner."""
    from agnusmail.modules.domains.models import DomainStatus, MailDomain

    local_part, separator, email_domain = email.strip().rpartition("@")
    email_domain = email_domain.lower()
    if not separator:
        raise ResourceNotFoundError()
    custom = None
    if email_domain != domain:
        custom = session.scalar(
            select(MailDomain.user_id).where(
                MailDomain.name == email_domain, MailDomain.status == DomainStatus.VERIFIED
            )
        )
        if custom is None:
            raise ResourceNotFoundError()
    try:
        normalized = rules.normalize(local_part)
    except rules.InvalidLocalPartError as exc:
        raise ResourceNotFoundError() from exc
    row = session.execute(
        select(MailAddress, User)
        .join(User, User.id == MailAddress.user_id)
        .where(
            MailAddress.domain == email_domain,
            MailAddress.local_part == normalized,
            MailAddress.status == AddressStatus.ACTIVE,
            User.status == UserStatus.ACTIVE,
        )
    ).one_or_none()
    if row is None or (custom is not None and row[0].user_id != custom):
        raise ResourceNotFoundError()
    return row[0], row[1]
