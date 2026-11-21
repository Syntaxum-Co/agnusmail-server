"""Agnusmail HTTP API application factory."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from apps.api.middleware.body_limit import (
    RequestBodyLimitMiddleware,
    RequestBodyTooLarge,
    body_too_large_response,
)
from apps.api.middleware.content_type import install_json_body_requirement
from apps.api.middleware.csrf import install_csrf_protection
from apps.api.middleware.limits import install_concurrency_limit, install_request_timeout
from apps.api.middleware.metrics import install_metrics
from apps.api.middleware.security import (
    install_cors,
    install_https_enforcement,
    install_ip_rate_limit,
    install_proxy_headers,
    install_security_headers,
)
from apps.api.routes import health
from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.core.config import Settings, get_settings
from agnusmail.core.exceptions import AgnusmailError, error_payload
from agnusmail.core.logging import ThrottledWarning, configure_logging, get_logger
from agnusmail.infrastructure.database.roles import check_runtime_role
from agnusmail.infrastructure.database.session import (
    dispose_engine,
    get_engine,
    init_session_factory,
)
from agnusmail.infrastructure.metrics import start_metrics
from agnusmail.infrastructure.object_storage import ObjectStorage, build_object_storage
from agnusmail.infrastructure.redis.client import RedisClient
from agnusmail.infrastructure.redis.rate_limit import RateLimiter
from agnusmail.modules.abuse.router import router as abuse_router
from agnusmail.modules.addresses.router import router as addresses_router
from agnusmail.modules.attachments.router import router as attachments_router
from agnusmail.modules.audit.router import router as audit_router
from agnusmail.modules.authentication.device_binding import router as device_binding_router
from agnusmail.modules.authentication.router import router as auth_router
from agnusmail.modules.authentication.stores import (
    DeviceChallengeStore,
    NonceStore,
    PasskeyChallengeStore,
    SessionStore,
)
from agnusmail.modules.devices.router import router as devices_router
from agnusmail.modules.domains.router import router as domains_router
from agnusmail.modules.folders.router import router as folders_router
from agnusmail.modules.inbound.router import router as gateway_router
from agnusmail.modules.keys.policy import DeviceCertificatePolicy
from agnusmail.modules.keys.router import router as keys_router
from agnusmail.modules.messages.router import router as messages_router
from agnusmail.modules.outbound.router import router as outbound_router
from agnusmail.modules.passkeys.router import router as passkeys_router
from agnusmail.modules.portal.router import router as portal_router
from agnusmail.modules.quotas.policy import QuotaPolicy
from agnusmail.modules.quotas.router import router as usage_router
from agnusmail.modules.recovery.router import router as recovery_router

API_V1_PREFIX = "/v1"
RATE_LIMIT_WARNING_INTERVAL_SECONDS = 60.0


def create_app(
    settings: Settings | None = None,
    *,
    redis: Any | None = None,
    session_factory: sessionmaker[Session] | None = None,
    object_storage: ObjectStorage | None = None,
) -> FastAPI:
    """Build the FastAPI application.

    ``redis`` and ``session_factory`` let tests inject in-memory backends; production
    builds a pooled Redis client and a PostgreSQL engine and owns their lifecycle.
    """
    settings = settings or get_settings()
    configure_logging(debug=settings.environment == "local")

    redis_owner: RedisClient | None = None
    if redis is None:
        redis_owner = RedisClient(settings)
        redis_owner.create_pool()
        redis = redis_owner.client()

    @asynccontextmanager
    async def lifespan(app_: FastAPI) -> AsyncIterator[None]:
        owns_engine = session_factory is None
        app_.state.db_session_factory = (
            init_session_factory(settings) if owns_engine else session_factory
        )
        try:
            if owns_engine:
                # Deployed environments refuse to serve as a superuser or table owner.
                await run_in_threadpool(
                    check_runtime_role, get_engine(), strict=settings.environment != "local"
                )
            start_metrics(settings)  # internal /metrics port, if configured
            yield
        finally:
            if owns_engine:
                dispose_engine()
            if redis_owner is not None:
                await redis_owner.dispose()

    app = FastAPI(title=settings.app_name, docs_url=None, redoc_url=None, lifespan=lifespan)
    app.state.settings = settings
    app.state.quota_policy = QuotaPolicy.from_settings(settings)
    app.state.db_session_factory = session_factory
    app.state.nonce_store = NonceStore(redis)
    app.state.device_challenge_store = DeviceChallengeStore(redis)
    app.state.object_storage = object_storage or build_object_storage(settings)
    app.state.passkey_challenge_store = PasskeyChallengeStore(redis)
    app.state.session_store = SessionStore(
        redis,
        idle_ttl_seconds=settings.session_cookie_max_age_seconds,
        absolute_ttl_seconds=settings.session_absolute_ttl_seconds,
        max_sessions_per_owner=settings.max_sessions_per_user,
    )
    # Protocol v1 device certificates: OpenPGP v6 validation + proof of possession.
    app.state.key_policy = DeviceCertificatePolicy(max_bytes=settings.max_public_key_bytes)
    limiter = RateLimiter(redis)

    async def rate_limit_check(client_ip: str) -> bool:
        return await limiter.check(
            f"ip:{client_ip}", settings.rate_limit_per_ip, settings.rate_limit_window_seconds
        )

    app.state.rate_limit_check = rate_limit_check
    app.state.rate_limiter = limiter
    # Shared by the IP middleware and the per-route/per-user dependencies.
    app.state.rate_limit_failures = ThrottledWarning(
        get_logger("agnusmail.rate_limit"),
        "rate_limit_backend_unavailable",
        RATE_LIMIT_WARNING_INTERVAL_SECONDS,
    )

    async def handle_domain_error(_request: Request, exc: Exception) -> JSONResponse:
        if not isinstance(exc, AgnusmailError):  # pragma: no cover - registration guarantees it
            raise exc
        return JSONResponse(
            status_code=exc.status_code,
            content=error_payload(exc.detail, exc.error_code),
        )

    async def handle_body_too_large(_request: Request, _exc: Exception) -> JSONResponse:
        return body_too_large_response()

    async def handle_validation_error(_request: Request, exc: Exception) -> JSONResponse:
        # Never echo the submitted values (FastAPI's default includes "input").
        errors = exc.errors() if isinstance(exc, RequestValidationError) else []
        fields = [
            {
                "loc": [str(part) for part in error.get("loc", ())],
                "type": str(error.get("type", "")),
                "msg": str(error.get("msg", "")),
            }
            for error in errors
        ]
        body = error_payload("invalid request", "VALIDATION_ERROR")
        body["error"]["fields"] = fields
        return JSONResponse(status_code=422, content=body)

    app.add_exception_handler(AgnusmailError, handle_domain_error)
    app.add_exception_handler(RequestBodyTooLarge, handle_body_too_large)
    app.add_exception_handler(RequestValidationError, handle_validation_error)

    health.install_default_checks(app, redis)
    app.include_router(health.router)
    # Versioned API surface; probes stay unversioned.
    app.include_router(auth_router, prefix=API_V1_PREFIX)
    app.include_router(device_binding_router, prefix=API_V1_PREFIX)
    app.include_router(passkeys_router, prefix=API_V1_PREFIX)
    app.include_router(messages_router, prefix=API_V1_PREFIX)
    app.include_router(attachments_router, prefix=API_V1_PREFIX)
    app.include_router(recovery_router, prefix=API_V1_PREFIX)
    app.include_router(devices_router, prefix=API_V1_PREFIX)
    app.include_router(keys_router, prefix=API_V1_PREFIX)
    app.include_router(audit_router, prefix=API_V1_PREFIX)
    app.include_router(addresses_router, prefix=API_V1_PREFIX)
    app.include_router(gateway_router, prefix=API_V1_PREFIX)
    app.include_router(outbound_router, prefix=API_V1_PREFIX)
    app.include_router(portal_router, prefix=API_V1_PREFIX)
    app.include_router(folders_router, prefix=API_V1_PREFIX)
    app.include_router(domains_router, prefix=API_V1_PREFIX)
    app.include_router(usage_router, prefix=API_V1_PREFIX)
    app.include_router(abuse_router, prefix=API_V1_PREFIX)

    # Middleware: each one added wraps the previous ones, so the LAST added is the
    # OUTERMOST. Security headers and proxy handling sit outside everything else so
    # every response (429, 503, 413, CORS preflight) carries the headers and every
    # layer sees the real client scheme/IP. The body limit is innermost so the
    # streaming check runs directly under the router (BaseHTTPMiddleware layers wrap
    # `receive` in task groups).
    app.add_middleware(RequestBodyLimitMiddleware, max_body_bytes=settings.max_request_body_bytes)
    install_json_body_requirement(app)
    install_https_enforcement(app, settings.force_https)
    install_csrf_protection(app, settings)
    install_ip_rate_limit(app)
    install_request_timeout(app, settings.request_timeout_seconds)
    install_concurrency_limit(app, settings.max_concurrent_requests)
    install_cors(app, settings)
    install_security_headers(app, settings.force_https)
    install_metrics(app)  # outermost: every response is counted, 429/503 included
    install_proxy_headers(app, settings.trusted_proxies)

    return app
