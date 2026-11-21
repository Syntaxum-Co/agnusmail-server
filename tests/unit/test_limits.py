"""Tests for request timeout, concurrency and body size limits."""

import asyncio
from collections.abc import AsyncIterator

from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient

from agnusmail.core.config import Settings
from agnusmail.testing.fakes import make_app, make_settings

TIGHT_SETTINGS = make_settings(request_timeout_seconds=1, max_concurrent_requests=1)
SMALL_BODY_SETTINGS = make_settings(max_request_body_bytes=100)
JSON = {"Content-Type": "application/json"}


def app_with_routes(settings: Settings, delay: float = 0.0) -> FastAPI:
    app, _ = make_app(settings)

    @app.get("/slow")
    async def slow() -> dict[str, str]:
        await asyncio.sleep(delay)
        return {"status": "done"}

    @app.post("/echo")
    async def echo(request: Request) -> dict[str, int]:
        return {"size": len(await request.body())}

    return app


def client(app: FastAPI) -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


async def test_request_timeout_returns_503() -> None:
    async with client(app_with_routes(TIGHT_SETTINGS, delay=2.0)) as c:
        response = await c.get("/slow")
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "REQUEST_TIMEOUT"
    assert response.headers["X-Content-Type-Options"] == "nosniff"


async def test_concurrency_limit_rejects_second_request() -> None:
    app = app_with_routes(TIGHT_SETTINGS, delay=0.3)
    results: list[int] = []

    async def call() -> None:
        async with client(app) as c:
            results.append((await c.get("/slow")).status_code)

    await asyncio.gather(call(), call())
    assert sorted(results) == [200, 503]


async def test_declared_oversize_body_returns_413() -> None:
    async with client(app_with_routes(SMALL_BODY_SETTINGS)) as c:
        response = await c.post("/echo", content=b"x" * 101, headers=JSON)
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "REQUEST_TOO_LARGE"


async def test_chunked_oversize_body_returns_413() -> None:
    async def chunks() -> AsyncIterator[bytes]:
        for _ in range(5):
            yield b"x" * 40

    async with client(app_with_routes(SMALL_BODY_SETTINGS)) as c:
        response = await c.post("/echo", content=chunks(), headers=JSON)
    assert "content-length" not in response.request.headers
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "REQUEST_TOO_LARGE"


async def test_body_within_limit_is_accepted() -> None:
    async with client(app_with_routes(SMALL_BODY_SETTINGS)) as c:
        response = await c.post("/echo", content=b"x" * 100, headers=JSON)
    assert response.status_code == 200
    assert response.json() == {"size": 100}


async def test_invalid_content_length_returns_400() -> None:
    app = app_with_routes(SMALL_BODY_SETTINGS)
    sent: list[dict[str, object]] = []

    async def receive() -> dict[str, object]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, object]) -> None:
        sent.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/echo",
        "raw_path": b"/echo",
        "query_string": b"",
        "root_path": "",
        "headers": [(b"host", b"test"), (b"content-length", b"-1")],
        "client": ("127.0.0.1", 1234),
        "server": ("test", 80),
    }
    await app(scope, receive, send)  # type: ignore[arg-type]
    assert sent[0]["status"] == 400
