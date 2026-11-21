"""Administration CLI: wallet-signed, two operators for every
change, everything recorded, metadata only."""

import json
import secrets
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_account.signers.local import LocalAccount
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.apps.admin import __main__ as cli
from agnusmail.infrastructure.database.roles import (
    ADMIN_ONLY_TABLES,
    ADMIN_TABLE_PRIVILEGES,
    RUNTIME_TABLE_PRIVILEGES,
)
from agnusmail.modules.abuse.models import AccountRestriction
from agnusmail.modules.admin.models import AdminAction
from agnusmail.modules.admin.signing import (
    SignatureRejectedError,
    Statement,
    authenticate,
)
from agnusmail.modules.audit.models import AuditEvent
from agnusmail.modules.identity.models import User
from tests.unit.fakes import make_session_factory, make_settings

SETTINGS = make_settings()


def sign(account: LocalAccount) -> Callable[[Statement], str]:
    def signer(statement: Statement) -> str:
        signed = account.sign_message(encode_defunct(text=statement.text()))
        return "0x" + bytes(signed.signature).hex().removeprefix("0x")

    return signer


@pytest.fixture
def factory() -> sessionmaker[Session]:
    return make_session_factory()


@pytest.fixture
def operators(factory: sessionmaker[Session]) -> tuple[LocalAccount, LocalAccount]:
    first, second = Account.create(), Account.create()
    for op in (first, second):
        assert command(factory, ["bootstrap-operator", op.address])[0] == 0
    return first, second


@pytest.fixture
def user(factory: sessionmaker[Session]) -> User:
    with factory() as session, session.begin():
        account = User(ethereum_address="0x" + secrets.token_hex(20))
        session.add(account)
        session.flush()
        return account


def command(
    factory: sessionmaker[Session],
    argv: list[str],
    signer: Callable[[Statement], str] | None = None,
    capsys: Any = None,
) -> tuple[int, Any]:
    args = cli.parser().parse_args(argv)
    code = cli.run(args, SETTINGS, factory, read=lambda _p: "", signer=signer)
    output = None
    if capsys is not None:
        text = capsys.readouterr().out
        output = json.loads(text) if text.strip().startswith(("{", "[")) else text
    return code, output


def request(factory: Any, signer: Any, kind: str, *params: str, capsys: Any) -> str:
    code, out = command(factory, ["request", kind, *params], signer, capsys)
    assert code == 0, out
    assert out["status"] == "pending"
    return str(out["action"])


def test_bootstrap_only_for_the_first_two(factory: sessionmaker[Session], operators: Any) -> None:
    from agnusmail.core.exceptions import AgnusmailError

    with pytest.raises(AgnusmailError):
        command(factory, ["bootstrap-operator", Account.create().address])


def test_a_change_needs_a_second_operator(
    factory: sessionmaker[Session], operators: Any, user: User, capsys: Any
) -> None:
    first, second = operators
    action = request(
        factory, sign(first), "suspend_account", f"account={user.ethereum_address}", capsys=capsys
    )
    from agnusmail.core.exceptions import InvalidStateError

    with pytest.raises(InvalidStateError):  # the requester cannot approve
        command(factory, ["approve", action], sign(first))
    code, out = command(factory, ["approve", action], sign(second), capsys)
    assert (code, out["status"]) == (0, "executed")
    with factory() as session:
        suspended = session.get(User, user.id)
        assert suspended is not None and suspended.status == "suspended"
        event = session.scalars(
            select(AuditEvent).where(AuditEvent.event_type == "admin.suspended")
        ).one()
        assert event.user_id == user.id
        assert event.details["requested_by"] == first.address.lower()
        assert event.details["approved_by"] == second.address.lower()
    # Approved once: a second approval finds nothing pending.
    with pytest.raises(InvalidStateError):
        command(factory, ["approve", action], sign(second))
    action = request(
        factory,
        sign(second),
        "reinstate_account",
        f"account={user.ethereum_address}",
        capsys=capsys,
    )
    code, out = command(factory, ["approve", action], sign(first), capsys)
    assert out["result"]["status"] == "active"


def test_strangers_replays_and_stale_signatures_are_refused(
    factory: sessionmaker[Session], operators: Any, user: User
) -> None:
    first, _ = operators
    now = datetime.now(UTC)
    statement = Statement.new("app.agnusmail", "query", "show", {"account": "x"}, now)
    with factory() as session, session.begin():
        with pytest.raises(SignatureRejectedError, match="not an active operator"):
            authenticate(session, statement, sign(Account.create())(statement), now)
    signature = sign(first)(statement)
    with factory() as session, session.begin():
        authenticate(session, statement, signature, now)
    with factory() as session, session.begin():
        with pytest.raises(SignatureRejectedError, match="already used"):
            authenticate(session, statement, signature, now)
    old = Statement.new("app.agnusmail", "query", "show", {}, now - timedelta(minutes=11))
    with factory() as session, session.begin():
        with pytest.raises(SignatureRejectedError, match="too old"):
            authenticate(session, old, sign(first)(old), now)
    # A signature authorizes exactly its own text.
    other = Statement.new("app.agnusmail", "query", "pending", {}, now)
    with factory() as session, session.begin():
        with pytest.raises(SignatureRejectedError):
            authenticate(session, other, sign(first)(statement), now)


def test_lift_rotation_and_operators(
    factory: sessionmaker[Session], operators: Any, user: User, capsys: Any
) -> None:
    first, second = operators
    with factory() as session, session.begin():
        session.add(
            AccountRestriction(
                user_id=user.id,
                reason="reports",
                restricted_until=datetime.now(UTC) + timedelta(days=3),
            )
        )
    lift = request(
        factory, sign(first), "lift_restriction", f"account={user.ethereum_address}", capsys=capsys
    )
    _, out = command(factory, ["approve", lift], sign(second), capsys)
    assert out["status"] == "executed"
    rotation = request(
        factory, sign(first), "record_rotation", "credential=dkim_key", capsys=capsys
    )
    _, out = command(factory, ["approve", rotation], sign(second), capsys)
    assert out["result"]["credential"] == "dkim_key"
    from agnusmail.modules.admin.service import ActionInvalidError

    with pytest.raises(ActionInvalidError):  # names only, never a value
        command(factory, ["request", "record_rotation", "credential=hunter2"], sign(first))
    # Removing would leave one operator: recorded as failed.
    removal = request(
        factory, sign(first), "remove_operator", f"address={second.address}", capsys=capsys
    )
    code, out = command(factory, ["approve", removal], sign(second), capsys)
    assert (code, out["status"]) == (1, "failed")
    third = Account.create()
    add = request(factory, sign(first), "add_operator", f"address={third.address}", capsys=capsys)
    command(factory, ["approve", add], sign(second), capsys)
    code, _ = command(factory, ["pending"], sign(third), capsys)
    assert code == 0


def test_show_is_metadata_only_and_recorded(
    factory: sessionmaker[Session], operators: Any, user: User, capsys: Any
) -> None:
    first, _ = operators
    code, out = command(factory, ["show", user.ethereum_address], sign(first), capsys)
    assert code == 0
    assert set(out) == {
        "account",
        "user_status",
        "created_at",
        "addresses",
        "storage",
        "restricted_until",
        "reporters_last_30_days",
        "active_devices",
    }
    with factory() as session:
        recorded = session.scalars(
            select(AdminAction).where(AdminAction.kind == "query_show")
        ).one()
        assert recorded.requested_by == first.address.lower()


def test_pending_actions_expire(
    factory: sessionmaker[Session], operators: Any, user: User, capsys: Any
) -> None:
    first, second = operators
    action = request(
        factory, sign(first), "suspend_account", f"account={user.ethereum_address}", capsys=capsys
    )
    with factory() as session, session.begin():
        row = session.get(AdminAction, uuid.UUID(action))
        assert row is not None
        row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    from agnusmail.core.exceptions import InvalidStateError

    with pytest.raises(InvalidStateError, match="expired"):
        command(factory, ["approve", action], sign(second))


def test_the_api_role_cannot_reach_operator_tables() -> None:
    assert not ADMIN_ONLY_TABLES & set(RUNTIME_TABLE_PRIVILEGES)
    assert ADMIN_ONLY_TABLES <= set(ADMIN_TABLE_PRIVILEGES)
    # The admin role reads metadata only: no message, key or attachment tables.
    for table in ("messages", "message_keys", "attachments", "public_keys", "recovery_backups"):
        assert table not in ADMIN_TABLE_PRIVILEGES
