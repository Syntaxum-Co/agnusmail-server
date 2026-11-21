"""Shared API schema types."""

from datetime import UTC, datetime
from typing import Annotated

from pydantic import AfterValidator


def _as_utc(value: datetime) -> datetime:
    """Timestamps are stored in UTC; drivers that drop the offset (SQLite) yield naive ones."""
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


UtcDatetime = Annotated[datetime, AfterValidator(_as_utc)]
