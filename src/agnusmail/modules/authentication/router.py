"""Authentication routes: SIWE nonce/verify, renewal, logout, session lookup.

Every login, denied login, logout and session revocation is an event in the user's audit
chain (DV-05). Sessions carry a public ``session_id`` (not the token) that links them.
"""

import secrets
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from agnusmail.core.config import Settings
from agnusmail.core.exceptions import NotAuthenticatedError, error_payload
from agnusmail.core.security import clear_session_cookie, set_session_cookie
from agnusmail.modules.audit.models import AuditEventType
from agnusmail.modules.authentication.audit import audit_session_event
from agnusmail.modules.authentication.dependencies import (
    CurrentSession,
    auth_rate_limit,
    request_fingerprint,
    session_token,
)
from agnusmail.modules.authentication.stores import NonceStore, SessionStore
from agnusmail.modules.identity.service import record_login
from agnusmail.modules.identity.siwe import MAX_MESSAGE_LENGTH, siwe_verify

router = APIRouter(prefix="/auth", tags=["auth"])


class SiweVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    message: str = Field(min_length=1, max_length=MAX_MESSAGE_LENGTH)
    # 65-byte ECDSA signature, hex encoded, optional 0x prefix.
    signature: str = Field(pattern=r"^(0x)?[0-9a-fA-F]{130}$")


def get_settings_dep(request: Request) -> Settings:
    return request.app.state.settings  # type: ignore[no-any-return]


def get_nonce_store(request: Request) -> NonceStore:
    return request.app.state.nonce_store  # type: ignore[no-any-return]


def get_session_store(request: Request) -> SessionStore:
    return request.app.state.session_store  # type: ignore[no-any-return]


SettingsDep = Annotated[Settings, Depends(get_settings_dep)]
NonceStoreDep = Annotated[NonceStore, Depends(get_nonce_store)]
SessionStoreDep = Annotated[SessionStore, Depends(get_session_store)]


@router.post("/siwe/nonce", dependencies=[Depends(auth_rate_limit)])
async def create_nonce(store: NonceStoreDep) -> dict[str, str]:
    """Create a single-use SIWE nonce with a TTL of 5 minutes."""
    return {"nonce": await store.create()}


@router.post("/siwe/verify", dependencies=[Depends(auth_rate_limit)])
async def verify_siwe(
    request: Request,
    payload: SiweVerifyRequest,
    settings: SettingsDep,
    nonce_store: NonceStoreDep,
    session_store: SessionStoreDep,
) -> JSONResponse:
    """Validate the signed SIWE message and create an opaque session."""
    result = await siwe_verify(
        payload.message,
        payload.signature,
        nonce_store,
        expected_domain=settings.siwe_domain,
        expected_uri=settings.siwe_uri,
        expected_chain_id=settings.siwe_chain_id,
        clock_skew_seconds=settings.siwe_clock_skew_seconds,
    )
    if not result.ok:
        return JSONResponse(
            status_code=401,
            content=error_payload(result.reason, "SIWE_VERIFICATION_FAILED"),
        )
    await limit_new_accounts(request, settings, result.address)
    client = request_fingerprint(request)
    session_id = secrets.token_hex(8)
    outcome = await run_in_threadpool(
        lambda: record_login(
            request.app.state.db_session_factory,
            result.address,
            session_id=session_id,
            client=client,
            on_account_created=request.app.state.extensions.account_created_hooks(),
        )
    )
    if not outcome.active:
        return JSONResponse(
            status_code=403, content=error_payload("account suspended", "ACCOUNT_SUSPENDED")
        )
    response, _token = await open_session(
        request,
        settings,
        session_store,
        user_id=str(outcome.user_id),
        address=result.address,
        session_id=session_id,
        client=client,
        method="siwe",
    )
    return response


async def limit_new_accounts(request: Request, settings: Settings, address: str) -> None:
    """A first login creates the account; count those per client IP and day."""
    from sqlalchemy.exc import SQLAlchemyError

    from agnusmail.modules.abuse import limits
    from agnusmail.modules.authentication.dependencies import client_ip
    from agnusmail.modules.identity.repository import get_by_address

    def exists() -> bool:
        try:
            with request.app.state.db_session_factory() as s:
                return get_by_address(s, address) is not None
        except SQLAlchemyError:
            return True  # database down: the login itself answers 503 next

    if await run_in_threadpool(exists):
        return
    await limits.consume(
        request,
        "new_accounts",
        client_ip(request),
        1,
        settings.new_accounts_per_ip_per_day,
        limits.DAY,
    )


async def open_session(
    request: Request,
    settings: Settings,
    session_store: SessionStore,
    *,
    user_id: str,
    address: str,
    session_id: str,
    client: dict[str, str],
    method: str,
) -> tuple[JSONResponse, str]:
    """Create the session cookie after a successful login (SIWE or passkey)."""
    await _revoke_previous(request, session_store, client)
    token = await session_store.create(
        owner=user_id,
        data={
            "user_id": user_id,
            "address": address,
            "session_id": session_id,
            "auth_method": method,
        },
        fingerprint=client,
    )
    response = JSONResponse(status_code=200, content={"authenticated": True, "user_id": user_id})
    set_session_cookie(response, token, settings, session_store.idle_ttl_seconds)
    return response, token


async def _revoke_previous(
    request: Request, session_store: SessionStore, client: dict[str, str]
) -> None:
    """A new login replaces the session cookie the browser still carried, if any."""
    previous = session_token(request)
    if not previous:
        return
    record = await session_store.get(previous)
    await session_store.revoke(previous)
    if record is not None:
        await audit_session_event(
            request,
            record.owner,
            AuditEventType.AUTH_SESSION_REVOKED,
            actor_client=client,
            details={"session": record.data.get("session_id"), "reason": "replaced_by_login"},
        )


@router.post("/renew")
async def renew_session(
    session: CurrentSession, settings: SettingsDep, session_store: SessionStoreDep
) -> JSONResponse:
    """Slide the session TTL, capped by the absolute session lifetime."""
    ttl = await session_store.renew(session.token)
    if ttl is None:
        raise NotAuthenticatedError()
    response = JSONResponse(status_code=200, content={"renewed": True, "expires_in": ttl})
    set_session_cookie(response, session.token, settings, ttl)
    return response


@router.post("/logout")
async def logout(
    request: Request, settings: SettingsDep, session_store: SessionStoreDep
) -> JSONResponse:
    """Revoke the caller's session. Idempotent: works without a valid session."""
    token = session_token(request)
    if token:
        record = await session_store.get(token)
        await session_store.revoke(token)
        if record is not None:
            await audit_session_event(
                request,
                record.owner,
                AuditEventType.AUTH_LOGOUT,
                actor_client=request_fingerprint(request),
                details={"session": record.data.get("session_id")},
            )
    response = JSONResponse(status_code=200, content={"logged_out": True})
    clear_session_cookie(response, settings)
    return response


@router.get("/session")
async def get_session(session: CurrentSession) -> JSONResponse:
    """Return session data for the caller's cookie, if valid."""
    return JSONResponse(status_code=200, content=session.record.data)
