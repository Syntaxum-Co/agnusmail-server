"""Run synchronous database work in a transaction, off the event loop.

Domain errors raised by the work propagate unchanged (and roll the transaction back).
Integrity errors (e.g. a concurrent request won a uniqueness race) become 409 CONFLICT;
any other database failure becomes 503 without leaking details.
"""

from collections.abc import Callable

from fastapi.concurrency import run_in_threadpool
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.core.exceptions import ConflictError, DatabaseUnavailableError
from agnusmail.core.logging import get_logger

log = get_logger(__name__)


def run_sync_transaction[T](
    factory: sessionmaker[Session] | None, work: Callable[[Session], T]
) -> T:
    if factory is None:
        raise DatabaseUnavailableError()
    try:
        with factory() as session, session.begin():
            return work(session)
    except IntegrityError as exc:
        log.warning("db_integrity_conflict", error_type=type(exc.orig).__name__)
        raise ConflictError() from exc
    except SQLAlchemyError as exc:
        log.error("db_operation_failed", error_type=type(exc).__name__)
        raise DatabaseUnavailableError() from exc


async def run_in_transaction[T](
    factory: sessionmaker[Session] | None, work: Callable[[Session], T]
) -> T:
    return await run_in_threadpool(run_sync_transaction, factory, work)
