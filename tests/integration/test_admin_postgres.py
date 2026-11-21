"""Administration on PostgreSQL with the real roles: the
admin CLI works as the admin role (audit chain included); the API's runtime role cannot
touch the operator tables."""

import secrets
from collections.abc import Iterator

import pytest
from apps.admin import __main__ as cli
from eth_account import Account
from sqlalchemy import Engine, create_engine, make_url, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.core.config import Settings
from agnusmail.infrastructure.database.roles import (
    ADMIN_TABLE_PRIVILEGES,
    check_runtime_role,
    provision_admin_role,
    provision_runtime_role,
)
from agnusmail.infrastructure.database.session import create_db_engine
from agnusmail.modules import models as _all_models  # noqa: F401  (resolves every FK)
from agnusmail.modules.admin.models import Operator
from agnusmail.modules.identity.models import User
from tests.unit.test_admin import sign

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def owner() -> Iterator[Engine]:
    engine = create_db_engine(Settings(_env_file=None))  # type: ignore[call-arg]
    try:
        yield engine
    finally:
        engine.dispose()


def role_engine(owner: Engine, provision: object, role: str) -> Engine:
    password = secrets.token_urlsafe(24)
    with owner.begin() as connection:
        provision(connection, role, password)  # type: ignore[operator]
    return create_engine(make_url(owner.url).set(username=role, password=password))


def test_runtime_role_cannot_touch_operator_tables(owner: Engine) -> None:
    runtime = role_engine(owner, provision_runtime_role, "agnusmail_app_admin_it")
    try:
        for statement in (
            "SELECT count(*) FROM operators",
            "SELECT count(*) FROM admin_actions",
            "INSERT INTO operators (id, address, status, added_at)"
            " VALUES (gen_random_uuid(), '0x" + "a" * 40 + "', 'active', now())",
        ):
            with runtime.connect() as connection, pytest.raises(DBAPIError):
                connection.execute(text(statement))
    finally:
        runtime.dispose()


def test_cli_as_the_admin_role(owner: Engine) -> None:
    admin = role_engine(owner, provision_admin_role, "agnusmail_admin_it")
    try:
        assert check_runtime_role(admin, strict=True, allowed=ADMIN_TABLE_PRIVILEGES) == []
        with Session(owner) as session, session.begin():  # a clean slate of operators
            session.query(Operator).delete()
            account = User(ethereum_address="0x" + secrets.token_hex(20))
            session.add(account)
            session.flush()
            user_id, address = account.id, account.ethereum_address
        factory = sessionmaker(bind=admin, expire_on_commit=False)
        settings = Settings(_env_file=None)  # type: ignore[call-arg]
        first, second = Account.create(), Account.create()

        def run(argv: list[str], signer: object = None) -> int:
            args = cli.parser().parse_args(argv)
            return cli.run(args, settings, factory, signer=signer)  # type: ignore[arg-type]

        for op in (first, second):
            assert run(["bootstrap-operator", op.address]) == 0
        args = cli.parser().parse_args(["request", "suspend_account", f"account={address}"])
        import io
        import json
        from contextlib import redirect_stdout

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            cli.run(args, settings, factory, signer=sign(first))
        action = json.loads(buffer.getvalue())["action"]
        assert run(["approve", action], sign(second)) == 0
        with Session(owner) as session:
            suspended = session.get(User, user_id)
            assert suspended is not None and suspended.status == "suspended"
            count = session.execute(
                text(
                    "SELECT count(*) FROM audit_events"
                    " WHERE user_id = :u AND event_type = 'admin.suspended'"
                ),
                {"u": user_id},
            ).scalar_one()
            assert count == 1
    finally:
        admin.dispose()
