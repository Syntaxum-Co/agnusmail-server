"""Structured logging via structlog.

Hard rule: never log email content, tokens, passwords, keys, or secrets.
As a defence in depth, the ``redact_sensitive`` processor masks any event field
whose name looks sensitive before rendering. Callers must still never pass such
values to the logger in the first place.
"""

import logging
import time
from collections.abc import MutableMapping
from typing import Any, TextIO, cast

import structlog
from structlog.typing import FilteringBoundLogger

REDACTED = "[REDACTED]"

# Substrings matched case-insensitively against event field names.
SENSITIVE_KEY_FRAGMENTS = (
    "authorization",
    "body",
    "content",
    "cookie",
    "dsn",
    "key",
    "message_text",
    "passphrase",
    "password",
    "private",
    "secret",
    "session",
    "signature",
    "token",
)


def _is_sensitive(key: str) -> bool:
    lowered = key.lower()
    return any(fragment in lowered for fragment in SENSITIVE_KEY_FRAGMENTS)


def redact_sensitive(
    _logger: Any, _method_name: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    """structlog processor: replace values of sensitive-looking fields."""
    for key in list(event_dict):
        if key != "event" and _is_sensitive(key):
            event_dict[key] = REDACTED
    return event_dict


def configure_logging(debug: bool = False, stream: TextIO | None = None) -> None:
    """JSON logs to ``stream`` (stdout by default; CLIs pass stderr to keep stdout clean)."""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(level=level, force=True)
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            redact_sensitive,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(file=stream),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> FilteringBoundLogger:
    return cast(FilteringBoundLogger, structlog.get_logger(name))


class ThrottledWarning:
    """Emit a warning at most once per interval, reporting how many were suppressed.

    For conditions that would otherwise log once per request (e.g. a backend outage).
    """

    def __init__(self, logger: FilteringBoundLogger, event: str, interval_seconds: float) -> None:
        self._logger = logger
        self._event = event
        self._interval = interval_seconds
        self._last = float("-inf")
        self._suppressed = 0

    def report(self) -> None:
        now = time.monotonic()
        if now - self._last >= self._interval:
            self._logger.warning(self._event, suppressed=self._suppressed)
            self._last = now
            self._suppressed = 0
        else:
            self._suppressed += 1
