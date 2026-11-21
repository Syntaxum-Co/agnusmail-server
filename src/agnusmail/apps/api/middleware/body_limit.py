"""Request body size limit enforced on the bytes actually received.

Checking only Content-Length is not enough: chunked requests carry no length.
This pure ASGI middleware rejects declared oversize bodies up front and also
counts the streamed bytes, aborting with 413 as soon as the limit is crossed.
"""

from fastapi import HTTPException
from fastapi.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from agnusmail.core.exceptions import error_payload


class RequestBodyTooLarge(HTTPException):
    """Raised while streaming a body that exceeds the limit.

    Subclasses HTTPException so FastAPI's body parser re-raises it unchanged
    instead of converting it into a generic 400.
    """

    def __init__(self) -> None:
        super().__init__(status_code=413, detail="payload too large")


def body_too_large_response() -> JSONResponse:
    return JSONResponse(
        status_code=413, content=error_payload("payload too large", "REQUEST_TOO_LARGE")
    )


class RequestBodyLimitMiddleware:
    def __init__(self, app: ASGIApp, max_body_bytes: int) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        for name, value in scope["headers"]:
            if name == b"content-length":
                if not value.isdigit():
                    await JSONResponse(
                        status_code=400,
                        content=error_payload("invalid content-length", "BAD_REQUEST"),
                    )(scope, receive, send)
                    return
                if int(value) > self.max_body_bytes:
                    await body_too_large_response()(scope, receive, send)
                    return

        received = 0
        response_started = False

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_body_bytes:
                    raise RequestBodyTooLarge()
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except Exception as exc:
            if response_started or not _is_body_too_large(exc):
                raise
            await body_too_large_response()(scope, receive, send)


def _is_body_too_large(exc: Exception) -> bool:
    if isinstance(exc, RequestBodyTooLarge):
        return True
    return isinstance(exc, ExceptionGroup) and exc.subgroup(RequestBodyTooLarge) is not None
