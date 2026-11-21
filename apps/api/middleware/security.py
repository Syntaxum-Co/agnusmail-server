"""Security middleware: proxy trust, HTTPS enforcement, headers, CORS, per-IP rate limit."""

from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from agnusmail.core.config import Settings
from agnusmail.core.exceptions import error_payload
from agnusmail.core.logging import get_logger

log = get_logger(__name__)

HSTS_MAX_AGE_SECONDS = 31536000
PROBE_PATHS = frozenset({"/healthz", "/readyz"})

RateLimitCheck = Callable[[str], Awaitable[bool]]
CallNext = Callable[[Request], Awaitable[Response]]


def install_proxy_headers(app: FastAPI, trusted_proxies: list[str]) -> None:
    """Honour X-Forwarded-Proto/-For only from configured reverse proxies.

    Without trusted proxies the headers are ignored, so clients cannot spoof the
    scheme (HTTPS enforcement) or their IP (rate limiting).
    """
    if trusted_proxies:
        app.add_middleware(ProxyHeadersMiddleware, trusted_hosts=trusted_proxies)


def install_https_enforcement(app: FastAPI, force_https: bool) -> None:
    @app.middleware("http")
    async def enforce_https(request: Request, call_next: CallNext) -> Response:
        # Probes are called over plain HTTP from inside the cluster/host.
        if not force_https or request.url.path in PROBE_PATHS:
            return await call_next(request)
        if request.url.scheme != "https":
            return JSONResponse(
                status_code=400,
                content=error_payload("https required", "HTTPS_REQUIRED"),
            )
        return await call_next(request)


def install_security_headers(app: FastAPI, force_https: bool) -> None:
    @app.middleware("http")
    async def add_headers(request: Request, call_next: CallNext) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        response.headers.setdefault("Cache-Control", "no-store")
        if force_https:
            response.headers["Strict-Transport-Security"] = (
                f"max-age={HSTS_MAX_AGE_SECONDS}; includeSubDomains"
            )
        return response


def install_cors(app: FastAPI, settings: Settings) -> None:
    if not settings.cors_allowed_origins:
        return  # deny by default: no CORS headers when no origins configured
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allowed_origins,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
        allow_credentials=True,
        max_age=600,
    )


def install_ip_rate_limit(app: FastAPI) -> None:
    """Per-IP fixed-window rate limit using ``app.state.rate_limit_check``.

    Liveness/readiness probes are exempt. A backend failure fails open, so a Redis
    outage degrades protection instead of taking the API down. The warning is
    throttled (one per interval, with the number of suppressed failures) so an
    outage does not flood the logs with one line per request.
    """

    @app.middleware("http")
    async def rate_limit(request: Request, call_next: CallNext) -> Response:
        check: RateLimitCheck | None = getattr(app.state, "rate_limit_check", None)
        if check is None or request.url.path in PROBE_PATHS:
            return await call_next(request)
        client_ip = request.client.host if request.client else "unknown"
        try:
            allowed = await check(client_ip)
        except Exception:
            app.state.rate_limit_failures.report()
            return await call_next(request)
        if not allowed:
            return JSONResponse(
                status_code=429,
                content=error_payload("rate limit exceeded", "RATE_LIMITED"),
            )
        return await call_next(request)
