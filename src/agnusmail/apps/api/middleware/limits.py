"""Request timeout and concurrency limits."""

import asyncio
from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from agnusmail.core.exceptions import error_payload

CallNext = Callable[[Request], Awaitable[Response]]


def install_request_timeout(app: FastAPI, timeout_seconds: int) -> None:
    """Return 503 REQUEST_TIMEOUT when a request exceeds the configured budget."""

    @app.middleware("http")
    async def enforce_timeout(request: Request, call_next: CallNext) -> Response:
        try:
            return await asyncio.wait_for(call_next(request), timeout=timeout_seconds)
        except TimeoutError:
            return JSONResponse(
                status_code=503,
                content=error_payload("request timeout", "REQUEST_TIMEOUT"),
            )


def install_concurrency_limit(app: FastAPI, max_concurrent: int) -> None:
    """Return 503 SERVER_BUSY when the concurrency budget is exhausted."""
    semaphore = asyncio.Semaphore(max_concurrent)

    @app.middleware("http")
    async def limit_concurrency(request: Request, call_next: CallNext) -> Response:
        if semaphore.locked():
            return JSONResponse(
                status_code=503,
                content=error_payload("server busy", "SERVER_BUSY"),
            )
        async with semaphore:
            return await call_next(request)
