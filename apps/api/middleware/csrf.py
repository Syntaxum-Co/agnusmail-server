"""CSRF protection for cookie-authenticated, state-changing requests.

Follows the OWASP CSRF cheat sheet: verify the ``Origin`` header against an allowlist
and use Fetch Metadata (``Sec-Fetch-Site``) as defence in depth. Browsers always send
``Origin`` on cross-origin unsafe requests, so a request from an untrusted origin is
rejected before reaching any handler. Requests without browser headers (CLI/server
clients) cannot carry a victim's cookies across sites and are allowed.

The check runs for every unsafe method, with or without a session cookie, so it also
prevents login CSRF (forcing a victim into the attacker's session).
"""

from collections.abc import Awaitable, Callable
from urllib.parse import urlsplit

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from agnusmail.core.config import Settings
from agnusmail.core.exceptions import error_payload
from agnusmail.core.logging import get_logger

log = get_logger(__name__)

UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
CallNext = Callable[[Request], Awaitable[Response]]


def origin_of(url: str) -> str | None:
    """Serialize scheme://host[:port] the way browsers send it in ``Origin``."""
    parts = urlsplit(url)
    if not parts.scheme or not parts.hostname:
        return None
    default_port = {"http": 80, "https": 443}.get(parts.scheme)
    port = f":{parts.port}" if parts.port and parts.port != default_port else ""
    return f"{parts.scheme}://{parts.hostname}{port}".lower()


def trusted_origins(settings: Settings) -> frozenset[str]:
    candidates = [*settings.cors_allowed_origins, settings.siwe_uri]
    return frozenset(o for o in (origin_of(c) for c in candidates) if o)


def _rejected() -> JSONResponse:
    return JSONResponse(
        status_code=403, content=error_payload("cross-site request rejected", "CSRF_REJECTED")
    )


def install_csrf_protection(app: FastAPI, settings: Settings) -> None:
    allowed = trusted_origins(settings)

    @app.middleware("http")
    async def csrf_protect(request: Request, call_next: CallNext) -> Response:
        if request.method not in UNSAFE_METHODS:
            return await call_next(request)

        own_origin = origin_of(str(request.base_url))
        origin = request.headers.get("origin")
        if origin is not None:
            normalized = origin_of(origin) if origin != "null" else None
            if normalized is None or (normalized != own_origin and normalized not in allowed):
                log.warning("csrf_rejected", reason="untrusted_origin", path=request.url.path)
                return _rejected()
            return await call_next(request)

        # No Origin: only browsers send Fetch Metadata; a cross-site browser request
        # without an Origin we can verify is refused.
        if request.headers.get("sec-fetch-site") == "cross-site":
            log.warning("csrf_rejected", reason="cross_site_fetch", path=request.url.path)
            return _rejected()
        return await call_next(request)
