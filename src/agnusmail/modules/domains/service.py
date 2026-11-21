"""Custom domains: add, verify by TXT, create addresses, remove."""

import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from agnusmail.core.config import MAIL_DOMAIN_PATTERN
from agnusmail.core.exceptions import (
    AgnusmailError,
    ConflictError,
    LimitExceededError,
    ResourceNotFoundError,
)
from agnusmail.modules.addresses import rules
from agnusmail.modules.addresses.models import AddressKind, AddressStatus, MailAddress
from agnusmail.modules.addresses.service import AddressInvalidError, AddressTakenError
from agnusmail.modules.audit.models import AuditEventType
from agnusmail.modules.audit.service import ActorContext, record_event
from agnusmail.modules.domains.models import (
    MAX_DOMAIN_ADDRESSES,
    MAX_DOMAINS,
    DomainStatus,
    MailDomain,
)

DOMAIN_NAME = re.compile(MAIL_DOMAIN_PATTERN)


class DomainInvalidError(AgnusmailError):
    status_code = 422
    message = "invalid domain"
    code = "DOMAIN_INVALID"


class DomainNotVerifiedError(AgnusmailError):
    status_code = 409
    message = "the verification TXT record was not found"
    code = "DOMAIN_NOT_VERIFIED"


class DomainTakenError(AgnusmailError):
    status_code = 409
    message = "another account controls this domain"
    code = "DOMAIN_TAKEN"


@dataclass(frozen=True)
class DnsRecord:
    type: str
    host: str
    value: str
    purpose: str


def records(
    domain: MailDomain, *, mail_domain: str, mx_host: str, selector: str
) -> list[DnsRecord]:
    """What the owner publishes. Only the first one is checked (proof of control)."""
    return [
        DnsRecord("TXT", domain.verification_host, domain.verification_value, "verification"),
        DnsRecord("MX", domain.name, f"10 {mx_host}", "receive mail through Agnusmail"),
        DnsRecord("TXT", domain.name, f"v=spf1 include:{mail_domain} -all", "SPF"),
        DnsRecord(
            "CNAME",
            f"{selector}._domainkey.{domain.name}",
            f"{selector}._domainkey.{mail_domain}",
            "DKIM (outbound signing with d=" + domain.name + ")",
        ),
        DnsRecord("TXT", f"_dmarc.{domain.name}", "v=DMARC1; p=quarantine", "DMARC (suggested)"),
    ]


def normalize_domain(name: str, mail_domain: str) -> str:
    value = name.strip().rstrip(".").lower()
    if not value.isascii() or len(value) > 253 or not DOMAIN_NAME.fullmatch(value):
        raise DomainInvalidError("use a DNS hostname such as example.com (ASCII)")
    if value == mail_domain or value.endswith("." + mail_domain):
        raise DomainInvalidError("the service's own domain cannot be added")
    return value


def own_domain(session: Session, owner_id: uuid.UUID, domain_id: uuid.UUID) -> MailDomain:
    domain = session.get(MailDomain, domain_id)
    if domain is None or domain.user_id != owner_id:
        raise ResourceNotFoundError()
    return domain


def add(session: Session, actor: ActorContext, name: str, mail_domain: str) -> MailDomain:
    value = normalize_domain(name, mail_domain)
    count = session.scalar(
        select(func.count()).select_from(MailDomain).where(MailDomain.user_id == actor.user_id)
    )
    if (count or 0) >= MAX_DOMAINS:
        raise LimitExceededError(f"at most {MAX_DOMAINS} domains per account")
    if session.scalar(
        select(MailDomain.id).where(MailDomain.user_id == actor.user_id, MailDomain.name == value)
    ):
        raise ConflictError("this domain was already added")
    domain = MailDomain(
        user_id=actor.user_id, name=value, status=DomainStatus.PENDING, token=secrets.token_hex(16)
    )
    session.add(domain)
    session.flush()
    record_event(
        session,
        actor,
        AuditEventType.DOMAIN_ADDED,
        owner_id=actor.user_id,
        details={"domain": value},
    )
    return domain


def _drop_addresses(session: Session, owner_id: uuid.UUID, name: str) -> int:
    result = session.execute(
        delete(MailAddress).where(
            MailAddress.user_id == owner_id,
            MailAddress.domain == name,
            MailAddress.kind == AddressKind.DOMAIN,
        )
    )
    return int(getattr(result, "rowcount", 0) or 0)


def verify(
    session: Session,
    actor: ActorContext,
    domain_id: uuid.UUID,
    txt_values: list[str],
    now: datetime,
) -> MailDomain:
    """``txt_values``: the TXT strings published at ``_agnusmail.<domain>``."""
    domain = own_domain(session, actor.user_id, domain_id)
    if domain.status == DomainStatus.VERIFIED:
        return domain
    if domain.verification_value not in txt_values:
        raise DomainNotVerifiedError(
            f"publish TXT {domain.verification_host} = {domain.verification_value}"
        )
    holder = session.scalars(
        select(MailDomain)
        .where(
            MailDomain.name == domain.name,
            MailDomain.status == DomainStatus.VERIFIED,
            MailDomain.user_id != actor.user_id,
        )
        .with_for_update()
    ).one_or_none()
    if holder is not None:
        if holder.verification_value in txt_values:
            raise DomainTakenError()
        # The previous holder no longer controls the DNS: the domain changes hands.
        removed = _drop_addresses(session, holder.user_id, holder.name)
        holder.status = DomainStatus.PENDING
        holder.verified_at = None
        session.flush()
        record_event(
            session,
            None,
            AuditEventType.DOMAIN_LOST,
            owner_id=holder.user_id,
            details={"domain": holder.name, "addresses_removed": removed},
            now=now,
        )
    domain.status = DomainStatus.VERIFIED
    domain.verified_at = now
    session.flush()
    record_event(
        session,
        actor,
        AuditEventType.DOMAIN_VERIFIED,
        owner_id=actor.user_id,
        details={"domain": domain.name},
        now=now,
    )
    return domain


def remove(session: Session, actor: ActorContext, domain_id: uuid.UUID) -> None:
    domain = own_domain(session, actor.user_id, domain_id)
    removed = _drop_addresses(session, actor.user_id, domain.name)
    session.delete(domain)
    session.flush()
    record_event(
        session,
        actor,
        AuditEventType.DOMAIN_REMOVED,
        owner_id=actor.user_id,
        details={"domain": domain.name, "addresses_removed": removed},
    )


def add_address(
    session: Session, actor: ActorContext, domain_id: uuid.UUID, requested: str
) -> MailAddress:
    """An address on a verified domain: the address registry's syntax, no reserved names
    (the domain is the owner's), unique by canonical form within the domain."""
    domain = own_domain(session, actor.user_id, domain_id)
    if domain.status != DomainStatus.VERIFIED:
        raise DomainNotVerifiedError("verify the domain first")
    try:
        local_part = rules.normalize(requested)
    except rules.InvalidLocalPartError as exc:
        raise AddressInvalidError(str(exc)) from exc
    session.execute(select(MailDomain.id).where(MailDomain.id == domain.id).with_for_update())
    count = session.scalar(
        select(func.count()).select_from(MailAddress).where(MailAddress.domain == domain.name)
    )
    if (count or 0) >= MAX_DOMAIN_ADDRESSES:
        raise LimitExceededError(f"at most {MAX_DOMAIN_ADDRESSES} addresses per domain")
    canonical = rules.canonical(local_part)
    if session.scalar(
        select(MailAddress.id).where(
            MailAddress.domain == domain.name, MailAddress.canonical == canonical
        )
    ):
        raise AddressTakenError()
    address = MailAddress(
        user_id=actor.user_id,
        local_part=local_part,
        canonical=canonical,
        domain=domain.name,
        status=AddressStatus.ACTIVE,
        kind=AddressKind.DOMAIN,
    )
    session.add(address)
    session.flush()
    record_event(
        session,
        actor,
        AuditEventType.ADDRESS_DOMAIN_CLAIMED,
        owner_id=actor.user_id,
        details={"address": address.email},
    )
    return address


def list_domains(session: Session, owner_id: uuid.UUID) -> list[MailDomain]:
    return list(
        session.scalars(
            select(MailDomain)
            .where(MailDomain.user_id == owner_id)
            .order_by(MailDomain.created_at, MailDomain.id)
        )
    )


def hosted(session: Session, domains: set[str]) -> set[str]:
    """Which of ``domains`` are verified custom domains (reached end to end)."""
    if not domains:
        return set()
    return set(
        session.scalars(
            select(MailDomain.name).where(
                MailDomain.name.in_(sorted(domains)), MailDomain.status == DomainStatus.VERIFIED
            )
        )
    )
