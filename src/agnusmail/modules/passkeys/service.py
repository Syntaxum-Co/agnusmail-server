"""Passkey use cases. Synchronous; run inside ``run_in_transaction``.

WebAuthn verification is done by py_webauthn; this module adds the account rules: the
wallet approves every passkey, user verification is mandatory, revoked credentials and
suspended accounts cannot log in, and every change is audited.
"""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import func, select
from sqlalchemy.orm import Session
from webauthn import verify_authentication_response, verify_registration_response
from webauthn.helpers.exceptions import WebAuthnException

from agnusmail.core.config import Settings
from agnusmail.core.exceptions import (
    AgnusmailError,
    ConflictError,
    InvalidStateError,
    LimitExceededError,
    ResourceNotFoundError,
)
from agnusmail.modules.audit.models import AuditEventType
from agnusmail.modules.audit.service import ActorContext, record_event
from agnusmail.modules.devices.attestation import AttestationError
from agnusmail.modules.devices.service import AttestationRejectedError
from agnusmail.modules.identity.models import User, UserStatus
from agnusmail.modules.passkeys.models import PasskeyCredential, PasskeyStatus
from agnusmail.modules.passkeys.wallet import PasskeyRegistrationClaim, verify_passkey_registration


class PasskeyRejectedError(AgnusmailError):
    """One answer for every failed passkey login: no hint about which check failed."""

    status_code = 401
    message = "passkey authentication failed"
    code = "PASSKEY_REJECTED"


class PasskeyRegistrationRejectedError(AgnusmailError):
    status_code = 422
    message = "passkey registration rejected"
    code = "PASSKEY_REGISTRATION_REJECTED"


@dataclass(frozen=True)
class RelyingParty:
    rp_id: str
    origin: str
    service: str  # protocol ``service`` for the wallet attestation
    chain_id: int


def relying_party(settings: Settings) -> RelyingParty:
    """WebAuthn RP id = the service host; origin = the one users log in from (SIWE URI)."""
    parts = urlsplit(settings.siwe_uri)
    return RelyingParty(
        rp_id=settings.siwe_domain.split(":")[0],
        origin=f"{parts.scheme}://{parts.netloc}",
        service=settings.siwe_domain,
        chain_id=settings.siwe_chain_id,
    )


@dataclass(frozen=True)
class WalletApproval:
    issued_at: int
    signature: str


def _account(session: Session, user_id: uuid.UUID) -> str:
    return session.scalars(select(User.ethereum_address).where(User.id == user_id)).one()


def register_passkey(
    session: Session,
    actor: ActorContext,
    credential: dict[str, Any],
    challenge: bytes,
    name: str,
    approval: WalletApproval,
    rp: RelyingParty,
    *,
    max_per_user: int,
    now: datetime,
) -> PasskeyCredential:
    try:
        verified = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=rp.rp_id,
            expected_origin=rp.origin,
            require_user_verification=True,
        )
    except WebAuthnException as exc:
        raise PasskeyRegistrationRejectedError(str(exc)) from exc

    claim = PasskeyRegistrationClaim(
        account=_account(session, actor.user_id),
        credential_id=verified.credential_id,
        service=rp.service,
        issued_at=approval.issued_at,
    )
    try:
        verify_passkey_registration(
            claim,
            bytes.fromhex(approval.signature.removeprefix("0x")),
            chain_id=rp.chain_id,
            now=now,
        )
    except AttestationError as exc:
        raise AttestationRejectedError(f"wallet approval rejected: {exc.reason}") from exc

    session.execute(select(User.id).where(User.id == actor.user_id).with_for_update())
    active = session.scalar(
        select(func.count())
        .select_from(PasskeyCredential)
        .where(
            PasskeyCredential.user_id == actor.user_id,
            PasskeyCredential.status == PasskeyStatus.ACTIVE,
        )
    )
    if int(active or 0) >= max_per_user:
        raise LimitExceededError("passkey limit reached; revoke one first")
    existing = session.scalar(
        select(PasskeyCredential.id).where(
            PasskeyCredential.credential_id == verified.credential_id
        )
    )
    if existing is not None:
        raise ConflictError("this passkey is already registered")

    passkey = PasskeyCredential(
        user_id=actor.user_id,
        credential_id=verified.credential_id,
        public_key=verified.credential_public_key,
        sign_count=verified.sign_count,
        name=name,
        backed_up=bool(verified.credential_backed_up),
        aaguid=str(verified.aaguid),
        wallet_signature=approval.signature.lower(),
        wallet_issued_at=datetime.fromtimestamp(approval.issued_at, tz=UTC),
        status=PasskeyStatus.ACTIVE,
    )
    session.add(passkey)
    session.flush()
    record_event(
        session,
        actor,
        AuditEventType.AUTH_PASSKEY_REGISTERED,
        owner_id=actor.user_id,
        details={"passkey": str(passkey.id), "backed_up": passkey.backed_up},
    )
    return passkey


@dataclass(frozen=True)
class PasskeyLogin:
    user_id: uuid.UUID
    address: str
    passkey_id: uuid.UUID
    active: bool


def authenticate(
    session: Session,
    credential: dict[str, Any],
    credential_id: bytes,
    challenge: bytes,
    rp: RelyingParty,
    *,
    session_id: str,
    client: dict[str, str],
    now: datetime,
) -> PasskeyLogin:
    """Verify an assertion and audit the login, in one transaction (like SIWE logins)."""
    passkey = session.scalars(
        select(PasskeyCredential)
        .where(PasskeyCredential.credential_id == credential_id)
        .with_for_update()
    ).one_or_none()
    if passkey is None or passkey.status != PasskeyStatus.ACTIVE:
        raise PasskeyRejectedError()
    try:
        verified = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=rp.rp_id,
            expected_origin=rp.origin,
            credential_public_key=passkey.public_key,
            credential_current_sign_count=passkey.sign_count,
            require_user_verification=True,
        )
    except WebAuthnException as exc:  # includes a non-increasing counter (cloned key)
        raise PasskeyRejectedError() from exc
    passkey.sign_count = verified.new_sign_count
    passkey.last_used_at = now

    user = session.get(User, passkey.user_id)
    assert user is not None
    active = user.status == UserStatus.ACTIVE
    if active:
        user.last_login_at = now
    record_event(
        session,
        ActorContext(user_id=user.id, client=dict(client)),
        AuditEventType.AUTH_LOGIN if active else AuditEventType.AUTH_LOGIN_DENIED,
        owner_id=user.id,
        details=(
            {"session": session_id, "method": "passkey", "passkey": str(passkey.id)}
            if active
            else {"reason": "account_suspended", "method": "passkey"}
        ),
    )
    return PasskeyLogin(user.id, user.ethereum_address, passkey.id, active)


def list_passkeys(session: Session, owner_id: uuid.UUID) -> list[PasskeyCredential]:
    rows = session.scalars(
        select(PasskeyCredential)
        .where(PasskeyCredential.user_id == owner_id)
        .order_by(PasskeyCredential.created_at)
    )
    return list(rows)


def revoke_passkey(
    session: Session, actor: ActorContext, passkey_id: uuid.UUID, now: datetime
) -> PasskeyCredential:
    passkey = session.scalars(
        select(PasskeyCredential)
        .where(PasskeyCredential.id == passkey_id, PasskeyCredential.user_id == actor.user_id)
        .with_for_update()
    ).one_or_none()
    if passkey is None:
        raise ResourceNotFoundError("passkey not found")
    if passkey.status == PasskeyStatus.REVOKED:
        raise InvalidStateError("passkey is already revoked")
    passkey.status = PasskeyStatus.REVOKED
    passkey.revoked_at = now
    session.flush()
    record_event(
        session,
        actor,
        AuditEventType.AUTH_PASSKEY_REVOKED,
        owner_id=actor.user_id,
        details={"passkey": str(passkey.id)},
    )
    return passkey
