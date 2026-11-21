"""Health (liveness) and readiness endpoints."""

import asyncio
import inspect
from collections.abc import Awaitable, Callable
from typing import Annotated, Any

from fastapi import APIRouter, Depends, FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from sqlalchemy import text

from agnusmail.core.exceptions import error_payload
from agnusmail.core.logging import get_logger
from agnusmail.infrastructure.redis.client import check_readiness

router = APIRouter()
log = get_logger(__name__)

# A check may be sync (run in a worker thread) or async (awaited on the loop).
ReadinessCheck = Callable[[], bool] | Callable[[], Awaitable[bool]]


def make_db_check(app: FastAPI) -> Callable[[], bool]:
    def db_check() -> bool:
        factory = app.state.db_session_factory
        if factory is None:
            raise RuntimeError("database not initialized")
        with factory() as session:
            session.execute(text("SELECT 1"))
        return True

    return db_check


async def run_check(name: str, check: ReadinessCheck, timeout_seconds: float) -> bool:
    """Run one check with a timeout; any failure means not ready (details never exposed)."""
    try:
        if inspect.iscoroutinefunction(check):
            result: Any = await asyncio.wait_for(check(), timeout_seconds)
        else:
            result = await asyncio.wait_for(run_in_threadpool(check), timeout_seconds)
        return bool(result)
    except Exception:
        log.warning("readiness_check_failed", check=name)
        return False


def get_checks(request: Request) -> dict[str, ReadinessCheck]:
    return {"db": request.app.state.db_check, "redis": request.app.state.redis_check}


@router.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/readyz")
async def readyz(
    request: Request,
    checks: Annotated[dict[str, ReadinessCheck], Depends(get_checks)],
) -> JSONResponse:
    timeout = request.app.state.settings.readiness_timeout_seconds
    results = await asyncio.gather(
        *(run_check(name, check, timeout) for name, check in checks.items())
    )
    if all(results):
        return JSONResponse(status_code=200, content={"status": "ready"})
    return JSONResponse(status_code=503, content=error_payload("not ready", "not_ready"))


def install_default_checks(app: FastAPI, redis_client: Any) -> None:
    async def redis_check() -> bool:
        return await check_readiness(redis_client)

    app.state.db_check = make_db_check(app)
    app.state.redis_check = redis_check
