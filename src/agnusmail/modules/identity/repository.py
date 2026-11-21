"""User registration and lookup by Ethereum address."""

import re
import uuid
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.orm import Session

from agnusmail.modules.identity.models import User

ADDRESS_REGEX = re.compile(r"^0x[0-9a-fA-F]{40}$")


class InvalidAddressError(ValueError):
    """Raised for strings that are not a 20-byte hex Ethereum address."""


def normalize_address(address: str) -> str:
    """Canonical storage form: lowercase hex. Case only carries the EIP-55 checksum."""
    if not ADDRESS_REGEX.match(address):
        raise InvalidAddressError("invalid ethereum address")
    return address.lower()


def get_by_address(session: Session, address: str) -> User | None:
    normalized = normalize_address(address)
    return session.scalars(select(User).where(User.ethereum_address == normalized)).one_or_none()


def get_by_id(session: Session, user_id: uuid.UUID) -> User | None:
    return session.get(User, user_id)


def register_login(session: Session, address: str, now: datetime) -> User:
    """Create the user on first login (idempotent and race-safe) and stamp the login.

    Uses INSERT ... ON CONFLICT DO NOTHING on the unique address, so concurrent first
    logins of the same address converge on a single row instead of failing.
    """
    normalized = normalize_address(address)
    values = {"id": uuid.uuid4(), "ethereum_address": normalized}
    conflict_target = [User.ethereum_address]
    dialect = session.get_bind().dialect.name
    if dialect == "postgresql":
        session.execute(
            postgresql.insert(User)
            .values(values)
            .on_conflict_do_nothing(index_elements=conflict_target)
        )
    elif dialect == "sqlite":
        session.execute(
            sqlite.insert(User)
            .values(values)
            .on_conflict_do_nothing(index_elements=conflict_target)
        )
    else:  # pragma: no cover - only PostgreSQL (prod) and SQLite (unit tests) are supported
        raise RuntimeError(f"unsupported database dialect: {dialect}")
    user = session.scalars(select(User).where(User.ethereum_address == normalized)).one()
    user.last_login_at = now
    return user
