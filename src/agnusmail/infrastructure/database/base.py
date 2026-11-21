"""Declarative base shared by every ORM model.

The naming convention gives every index/constraint a deterministic name, so
Alembic migrations can reference (and later drop/alter) them reliably.
"""

from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase

# The *_N_* tokens join every column of multi-column constraints (single-column names
# are unchanged), so composite constraints get distinct, readable names.
NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)
