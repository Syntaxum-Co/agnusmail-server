"""Administration CLI — run on the server, never exposed.

    python -m agnusmail.apps.admin bootstrap-operator 0x...        # first two operators only
    python -m agnusmail.apps.admin request suspend_account account=0x...   # or account=name@domain
    python -m agnusmail.apps.admin approve <action-id>             # a different operator
    python -m agnusmail.apps.admin show <account>                  # metadata, one operator
    python -m agnusmail.apps.admin pending                          # pending actions, one operator

Each command (except the bootstrap) prints a message; the operator signs it in their own
wallet (``personal_sign``: MetaMask, hardware wallet, ``cast wallet sign``) and pastes
the signature (or passes ``--signature``). Changes need a second operator's approval.
Runs as the admin database role (``ADMIN_TABLE_PRIVILEGES``); outside the local
environment it refuses any privilege beyond that map. Output is JSON on stdout.
"""

import argparse
import json
import sys
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session, sessionmaker

from agnusmail.core.config import Settings, get_settings
from agnusmail.core.exceptions import AgnusmailError
from agnusmail.core.logging import configure_logging
from agnusmail.extensions import from_settings
from agnusmail.infrastructure.database.roles import ADMIN_TABLE_PRIVILEGES, check_runtime_role
from agnusmail.infrastructure.database.session import create_db_engine
from agnusmail.modules import models as _all_models  # noqa: F401  (resolves every FK)
from agnusmail.modules.admin import service
from agnusmail.modules.admin.models import AdminAction
from agnusmail.modules.admin.signing import Statement, authenticate

Reader = Callable[[str], str]
Signer = Callable[[Statement], str]  # tests and automation: sign the exact statement


def _out(data: Any) -> None:
    print(json.dumps(data, indent=2, sort_keys=True, default=str))


def _signature(statement: Statement, given: str | None, read: Reader, signer: Signer | None) -> str:
    if signer is not None:
        return signer(statement)
    if given:
        return given
    print("Sign this message in your wallet (personal_sign) and paste the signature:")
    print("-" * 60)
    print(statement.text())
    print("-" * 60)
    return read("signature> ").strip()


def _params(pairs: list[str]) -> dict[str, Any]:
    params: dict[str, Any] = {}
    for pair in pairs:
        name, separator, value = pair.partition("=")
        if not separator or not name:
            raise service.ActionInvalidError(f"parameters are name=value, got {pair!r}")
        params[name] = value
    return params


def run(
    args: argparse.Namespace,
    settings: Settings,
    factory: "sessionmaker[Session]",
    read: Reader = input,
    signer: Signer | None = None,
) -> int:
    extensions = from_settings(settings)
    ctx = service.Context(
        extensions.quota_policy(settings),
        settings.mail_domain,
        changes=service.changes_for(extensions),
        account_details=extensions.admin_account_details(),
    )
    domain = settings.siwe_domain
    now = datetime.now(UTC)

    if args.command == "bootstrap-operator":
        with factory() as s, s.begin():
            added = service.bootstrap(s, args.address, now)
            _out({"operator": added.address, "status": added.status})
        return 0

    if args.command == "request":
        params = _params(args.params)
        with factory() as s:
            params = service.validate(args.kind, params, ctx)
        statement = Statement.new(domain, "request", args.kind, params, now)
        signature = _signature(statement, args.signature, read, signer)
        with factory() as s, s.begin():
            operator = authenticate(s, statement, signature, datetime.now(UTC))
            action = service.request(s, operator, args.kind, params, ctx, datetime.now(UTC))
            _out({"action": str(action.id), "status": action.status, "kind": action.kind})
        return 0

    if args.command == "approve":
        action_id = uuid.UUID(args.action_id)
        with factory() as s:
            found = s.get(AdminAction, action_id)
            if found is None:
                raise AgnusmailError("no such action")
            kind, params = found.kind, dict(found.params)
        statement = Statement.new(domain, "approve", kind, params, now, action_id=str(action_id))
        signature = _signature(statement, args.signature, read, signer)
        with factory() as s, s.begin():
            moment = datetime.now(UTC)
            operator = authenticate(s, statement, signature, moment)
            action = service.pending_action(s, action_id, moment)
            action = service.approve(s, operator, action, ctx, moment)
            _out({"action": str(action.id), "status": action.status, "result": action.result})
        return 0 if action.status == "executed" else 1

    if args.command in ("show", "pending"):
        params = {"account": args.account} if args.command == "show" else {}
        statement = Statement.new(domain, "query", args.command, params, now)
        signature = _signature(statement, args.signature, read, signer)
        with factory() as s, s.begin():
            moment = datetime.now(UTC)
            operator = authenticate(s, statement, signature, moment)
            if args.command == "show":
                data: Any = service.show_account(s, args.account, ctx, moment)
            else:
                data = service.list_pending(s, moment)
            # Queries are recorded too (who looked at which account).
            s.add(
                AdminAction(
                    kind=f"query_{args.command}",
                    params=params,
                    status="executed",
                    requested_by=operator,
                    requested_at=moment,
                    expires_at=moment,
                )
            )
            _out(data)
        return 0
    return 2


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="python -m agnusmail.apps.admin")
    commands = root.add_subparsers(dest="command", required=True)
    boot = commands.add_parser("bootstrap-operator")
    boot.add_argument("address")
    req = commands.add_parser("request")
    req.add_argument("kind", help="the change, e.g. suspend_account (extensions add more)")
    req.add_argument("params", nargs="*", help="name=value")
    req.add_argument("--signature")
    app = commands.add_parser("approve")
    app.add_argument("action_id")
    app.add_argument("--signature")
    show = commands.add_parser("show")
    show.add_argument("account")
    show.add_argument("--signature")
    pending = commands.add_parser("pending")
    pending.add_argument("--signature")
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    settings = get_settings()
    configure_logging(debug=False)
    engine = create_db_engine(settings)
    try:
        allowed = from_settings(settings).privileges("admin", ADMIN_TABLE_PRIVILEGES)
        check_runtime_role(engine, strict=settings.environment != "local", allowed=allowed)
        factory = sessionmaker(bind=engine, expire_on_commit=False)
        return run(args, settings, factory)
    except AgnusmailError as exc:
        print(json.dumps({"error": exc.error_code, "detail": exc.detail}), file=sys.stderr)
        return 1
    finally:
        engine.dispose()


if __name__ == "__main__":
    sys.exit(main())
