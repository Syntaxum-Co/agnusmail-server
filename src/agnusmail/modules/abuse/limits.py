"""Per-account and per-IP abuse limits on Redis.

Limit hits are logged (``abuse_limit_hit``: kind and account, no content). Fail-open by
default (a Redis outage must not stop internal mail or logins); outbound sending uses its
own fail-closed limits.
"""

from fastapi import Request

from agnusmail.core.exceptions import RateLimitedError, RedisUnavailableError
from agnusmail.core.logging import get_logger
from agnusmail.infrastructure.metrics import ABUSE_LIMIT_HITS

log = get_logger(__name__)

HOUR = 3600
DAY = 86400


async def consume(
    request: Request,
    kind: str,
    subject: str,
    amount: int,
    limit: int,
    window: int,
    *,
    fail_closed: bool = False,
) -> None:
    limiter = request.app.state.rate_limiter
    try:
        allowed = await limiter.consume(f"abuse:{kind}:{subject}", amount, limit, window)
    except Exception as exc:
        request.app.state.rate_limit_failures.report()
        if fail_closed:
            raise RedisUnavailableError() from exc
        return
    if not allowed:
        log.warning("abuse_limit_hit", kind=kind, subject=subject)
        ABUSE_LIMIT_HITS.labels(kind=kind).inc()  # the kind only, never the subject
        raise RateLimitedError(f"limit reached: {kind.replace('_', ' ')}")
