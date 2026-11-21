"""Integration tests share one real Redis: start each test with no rate-limit counters.

All test clients come from the same address ("testclient", 127.0.0.1), so the API's login
limit and the gateway's per-IP hourly limits would otherwise carry over between tests
and between runs, and fail whichever test happens to come later.
"""

import os
from collections.abc import Iterator

import pytest
import redis

from agnusmail.core.constants import RATE_LIMIT_KEY_PREFIX


@pytest.fixture(autouse=True)
def _fresh_rate_limits() -> Iterator[None]:
    url = os.environ.get("AGNUSMAIL_REDIS_URL")
    if url:
        client = redis.Redis.from_url(url, socket_connect_timeout=2)
        try:
            keys = list(client.scan_iter(match=f"{RATE_LIMIT_KEY_PREFIX}*", count=1000))
            if keys:
                client.delete(*keys)
        except redis.RedisError:
            pass  # tests that need Redis report it themselves
        finally:
            client.close()
    yield
