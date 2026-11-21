"""HTTP metrics: requests and latency per route *template*.

The label is the matched route's path template (``/v1/messages/{message_id}``), never
the raw URL: ids, addresses and tokens in paths never become label values. Requests that
match no route are counted as ``unmatched``.
"""

import time
from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response

from agnusmail.infrastructure.metrics import HTTP_LATENCY, HTTP_REQUESTS

CallNext = Callable[[Request], Awaitable[Response]]


def install_metrics(app: FastAPI) -> None:
    @app.middleware("http")
    async def measure(request: Request, call_next: CallNext) -> Response:
        started = time.perf_counter()
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
            return response
        finally:
            route = request.scope.get("route")
            template = getattr(route, "path", None) or "unmatched"
            HTTP_REQUESTS.labels(request.method, template, str(status)).inc()
            HTTP_LATENCY.labels(request.method, template).observe(time.perf_counter() - started)
