"""Database engine and session management (SQLAlchemy 2 / Psycopg 3)."""

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.core.config import Settings

_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def create_db_engine(settings: Settings) -> Engine:
    """Build the engine once per process."""
    return create_engine(
        settings.database_url,
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_max_overflow,
        pool_timeout=settings.db_pool_timeout_seconds,
        pool_pre_ping=True,
        connect_args={
            "connect_timeout": settings.db_connect_timeout_seconds,
            "options": f"-c statement_timeout={settings.db_statement_timeout_ms}",
        },
    )


def alembic_config_value(url: str) -> str:
    """Escape a DSN for Alembic's ConfigParser, where '%' starts an interpolation.

    URL-encoded passwords (e.g. 'p%40ss') would otherwise make Alembic crash.
    """
    return url.replace("%", "%%")


def init_session_factory(settings: Settings) -> sessionmaker[Session]:
    global _engine, _session_factory
    _engine = create_db_engine(settings)
    _session_factory = sessionmaker(bind=_engine, expire_on_commit=False)
    return _session_factory


def get_engine() -> Engine:
    if _engine is None:
        raise RuntimeError("database engine not initialized; call init_session_factory() first")
    return _engine


def get_session() -> Iterator[Session]:
    """FastAPI dependency session."""
    if _session_factory is None:
        raise RuntimeError("session factory not initialized; call init_session_factory() first")
    session = _session_factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional scope for workers and scripts."""
    if _session_factory is None:
        raise RuntimeError("session factory not initialized; call init_session_factory() first")
    session = _session_factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def dispose_engine() -> None:
    """Dispose the process-wide engine (call on application shutdown)."""
    global _engine, _session_factory
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _session_factory = None
