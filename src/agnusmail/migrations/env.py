"""Alembic environment.

The database URL comes from ``AGNUSMAIL_DATABASE_URL`` and is never logged. Extensions
listed in ``AGNUSMAIL_EXTENSIONS`` are imported first, so their models are part of the
metadata; their migrations live in their own version location (docs/extensions.md).
"""

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from agnusmail.extensions import from_environment
from agnusmail.infrastructure.database.base import Base
from agnusmail.infrastructure.database.session import alembic_config_value
from agnusmail.modules import models as _all_models  # noqa: F401  (registers every table)

config = context.config

database_url = os.environ.get("AGNUSMAIL_DATABASE_URL")
if not database_url:
    raise SystemExit("AGNUSMAIL_DATABASE_URL is required to run migrations")
config.set_main_option("sqlalchemy.url", alembic_config_value(database_url))

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

from_environment()  # importing an extension registers its tables on Base.metadata
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Emit the SQL instead of running it (``alembic upgrade head --sql``)."""
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
