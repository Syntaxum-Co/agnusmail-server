"""Require JSON bodies on state-changing requests.

Every API body is JSON. Rejecting other media types with 415 removes ambiguity in
parsing and closes the "simple request" path (form/text bodies) that browsers send
cross-site without a CORS preflight.
"""

from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from agnusmail.core.exceptions import error_payload

UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
CallNext = Callable[[Request], Awaitable[Response]]


def _has_body(request: Request) -> bool:
    length = request.headers.get("content-length")
    if length is not None:
        return length.isdigit() and int(length) > 0
    return "chunked" in request.headers.get("transfer-encoding", "").lower()


def _is_json(content_type: str) -> bool:
    media_type = content_type.split(";", 1)[0].strip().lower()
    return media_type == "application/json"


def install_json_body_requirement(app: FastAPI, exempt: frozenset[str] = frozenset()) -> None:
    """``exempt``: exact paths called by third parties that may not label their JSON
    (webhooks added by extensions, which must parse and authenticate the body themselves)."""

    @app.middleware("http")
    async def require_json(request: Request, call_next: CallNext) -> Response:
        if (
            request.url.path not in exempt
            and request.method in UNSAFE_METHODS
            and _has_body(request)
            and not _is_json(request.headers.get("content-type", ""))
        ):
            return JSONResponse(
                status_code=415,
                content=error_payload(
                    "content type must be application/json", "UNSUPPORTED_MEDIA_TYPE"
                ),
            )
        return await call_next(request)
