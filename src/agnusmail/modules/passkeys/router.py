"""Passkey routes: registration (logged in + wallet approval) and login.

- ``POST /v1/auth/passkeys/registration/options`` → WebAuthn creation options.
- ``POST /v1/auth/passkeys/registration`` → credential + EIP-712 wallet approval.
- ``POST /v1/auth/passkeys/authentication/options`` → request options (no session).
- ``POST /v1/auth/passkeys/authentication`` → assertion; opens a session like SIWE.
- ``GET /v1/auth/passkeys`` and ``POST /v1/auth/passkeys/{id}/revoke``.
"""

import base64
import binascii
import json
import secrets
import uuid
from datetime import UTC, datetime
from typing import Any

from eth_utils.address import to_checksum_address
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from webauthn import generate_authentication_options, generate_registration_options
from webauthn.helpers import options_to_json
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from agnusmail.core.config import Settings
from agnusmail.core.exceptions import error_payload
from agnusmail.core.logging import get_logger
from agnusmail.core.schemas import UtcDatetime
from agnusmail.infrastructure.database.transaction import run_in_transaction
from agnusmail.modules.authentication.dependencies import (
    CurrentSession,
    DbSessionFactory,
    RecentSession,
    actor_context,
    auth_rate_limit,
    request_fingerprint,
)
from agnusmail.modules.authentication.router import open_session
from agnusmail.modules.authentication.stores import PasskeyChallengeStore, SessionStore
from agnusmail.modules.devices.schemas import WALLET_SIGNATURE_PATTERN, UnixSeconds, clean_label
from agnusmail.modules.passkeys import service
from agnusmail.modules.passkeys.models import PASSKEY_NAME_MAX_LENGTH, PasskeyCredential

log = get_logger(__name__)

router = APIRouter(prefix="/auth/passkeys", tags=["auth"])

RP_NAME = "Agnusmail"
MAX_CREDENTIAL_JSON_BYTES = 16 * 1024


def _b64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _bounded_credential(value: dict[str, Any]) -> dict[str, Any]:
    if len(json.dumps(value)) > MAX_CREDENTIAL_JSON_BYTES:
        raise ValueError("credential too large")
    extensions = value.get("clientExtensionResults")
    prf = extensions.get("prf") if isinstance(extensions, dict) else None
    if isinstance(prf, dict) and "results" in prf:
        # The PRF output unlocks the device's private key: it never leaves the
        # browser. A client that forwards it has a bug; refuse rather than receive it.
        raise ValueError("clientExtensionResults.prf.results must not be sent")
    return value


class WalletApprovalIn(BaseModel):
    """EIP-712 PasskeyRegistration signed by the account's wallet."""

    model_config = ConfigDict(extra="forbid", strict=True)

    issued_at: UnixSeconds
    signature: str = Field(pattern=WALLET_SIGNATURE_PATTERN)


class PasskeyRegistrationIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    name: str = Field(min_length=1, max_length=PASSKEY_NAME_MAX_LENGTH)
    credential: dict[str, Any]  # RegistrationResponseJSON from navigator.credentials.create
    wallet_approval: WalletApprovalIn

    @field_validator("name")
    @classmethod
    def _clean_name(cls, value: str) -> str:
        return clean_label(value)

    @field_validator("credential")
    @classmethod
    def _bounded(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _bounded_credential(value)


class PasskeyAuthenticationIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    credential: dict[str, Any]  # AuthenticationResponseJSON from navigator.credentials.get

    @field_validator("credential")
    @classmethod
    def _bounded(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _bounded_credential(value)


class PasskeyOut(BaseModel):
    id: uuid.UUID
    name: str
    status: str
    backed_up: bool
    created_at: UtcDatetime
    last_used_at: UtcDatetime | None
    revoked_at: UtcDatetime | None

    @classmethod
    def from_row(cls, row: PasskeyCredential) -> "PasskeyOut":
        return cls(
            id=row.id,
            name=row.name,
            status=row.status,
            backed_up=row.backed_up,
            created_at=row.created_at,
            last_used_at=row.last_used_at,
            revoked_at=row.revoked_at,
        )


class PasskeyList(BaseModel):
    items: list[PasskeyOut]


def _settings(request: Request) -> Settings:
    return request.app.state.settings  # type: ignore[no-any-return]


def _challenges(request: Request) -> PasskeyChallengeStore:
    return request.app.state.passkey_challenge_store  # type: ignore[no-any-return]


def _session_store(request: Request) -> SessionStore:
    return request.app.state.session_store  # type: ignore[no-any-return]


@router.post("/registration/options")
async def registration_options(
    request: Request, session: CurrentSession, db: DbSessionFactory
) -> dict[str, Any]:
    rp = service.relying_party(_settings(request))
    owner = uuid.UUID(session.user_id)
    existing = await run_in_transaction(db, lambda s: service.list_passkeys(s, owner))
    challenge = await _challenges(request).create_registration(
        _session_store(request).digest(session.token)
    )
    options = generate_registration_options(
        rp_id=rp.rp_id,
        rp_name=RP_NAME,
        user_id=owner.bytes,
        user_name=str(session.record.data["address"]),
        challenge=challenge,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=[PublicKeyCredentialDescriptor(id=p.credential_id) for p in existing],
    )
    return json.loads(options_to_json(options))  # type: ignore[no-any-return]


@router.post("/registration", status_code=201)
async def register(
    request: Request, payload: PasskeyRegistrationIn, session: CurrentSession, db: DbSessionFactory
) -> PasskeyOut:
    settings = _settings(request)
    rp = service.relying_party(settings)
    challenge = await _challenges(request).consume_registration(
        _session_store(request).digest(session.token)
    )
    if challenge is None:
        raise service.PasskeyRegistrationRejectedError("no pending registration challenge")
    actor = actor_context(request, session)
    approval = service.WalletApproval(
        issued_at=payload.wallet_approval.issued_at, signature=payload.wallet_approval.signature
    )
    now = datetime.now(UTC)
    return await run_in_transaction(
        db,
        lambda s: PasskeyOut.from_row(
            service.register_passkey(
                s,
                actor,
                payload.credential,
                challenge,
                payload.name,
                approval,
                rp,
                max_per_user=settings.max_passkeys_per_user,
                now=now,
            )
        ),
    )


@router.get("")
async def list_passkeys(session: CurrentSession, db: DbSessionFactory) -> PasskeyList:
    owner = uuid.UUID(session.user_id)
    return await run_in_transaction(
        db,
        lambda s: PasskeyList(
            items=[PasskeyOut.from_row(p) for p in service.list_passkeys(s, owner)]
        ),
    )


@router.post("/{passkey_id}/revoke")
async def revoke(
    request: Request, passkey_id: uuid.UUID, session: RecentSession, db: DbSessionFactory
) -> PasskeyOut:
    actor = actor_context(request, session)
    now = datetime.now(UTC)
    revoked = await run_in_transaction(
        db, lambda s: PasskeyOut.from_row(service.revoke_passkey(s, actor, passkey_id, now))
    )
    try:
        await _session_store(request).revoke_passkey_sessions(str(passkey_id))
    except Exception as exc:  # Redis down: logged; the passkey itself is already revoked
        log.error("passkey_sessions_revoke_failed", error_type=type(exc).__name__)
    return revoked


@router.post("/authentication/options", dependencies=[Depends(auth_rate_limit)])
async def authentication_options(request: Request) -> dict[str, Any]:
    rp = service.relying_party(_settings(request))
    challenge = await _challenges(request).create_authentication()
    options = generate_authentication_options(
        rp_id=rp.rp_id,
        challenge=challenge,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    return json.loads(options_to_json(options))  # type: ignore[no-any-return]


def _assertion_parts(credential: dict[str, Any]) -> tuple[bytes, bytes]:
    """Credential id and the challenge the browser signed (from clientDataJSON)."""
    try:
        credential_id = _b64url(str(credential["rawId"]))
        client_data = json.loads(_b64url(str(credential["response"]["clientDataJSON"])))
        challenge = _b64url(str(client_data["challenge"]))
    except (KeyError, TypeError, ValueError, binascii.Error) as exc:
        raise service.PasskeyRejectedError() from exc
    return credential_id, challenge


@router.post("/authentication", dependencies=[Depends(auth_rate_limit)])
async def authenticate(
    request: Request, payload: PasskeyAuthenticationIn, db: DbSessionFactory
) -> JSONResponse:
    settings = _settings(request)
    rp = service.relying_party(settings)
    credential_id, challenge = _assertion_parts(payload.credential)
    # Only challenges we issued, once each; the library then checks the signature over it.
    if not await _challenges(request).consume_authentication(challenge):
        raise service.PasskeyRejectedError()
    client = request_fingerprint(request)
    session_id = secrets.token_hex(8)
    now = datetime.now(UTC)
    outcome = await run_in_transaction(
        db,
        lambda s: service.authenticate(
            s,
            payload.credential,
            credential_id,
            challenge,
            rp,
            session_id=session_id,
            client=client,
            now=now,
        ),
    )
    if not outcome.active:
        return JSONResponse(
            status_code=403, content=error_payload("account suspended", "ACCOUNT_SUSPENDED")
        )
    store = _session_store(request)
    response, token = await open_session(
        request,
        settings,
        store,
        user_id=str(outcome.user_id),
        address=to_checksum_address(outcome.address),
        session_id=session_id,
        client=client,
        method="passkey",
    )
    await store.index_by_passkey(token, str(outcome.passkey_id))
    return response
