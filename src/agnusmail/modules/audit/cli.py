"""Audit maintenance CLI, run by the operator or a scheduler.

    python -m agnusmail.modules.audit verify [--user UUID ...]
    python -m agnusmail.modules.audit purge [--dry-run] [--user UUID ...]

Prints one JSON summary on stdout (logs go to stderr). Exit status 0 when every chain
verifies / every purge succeeded, 1 otherwise. Never prints event details.
"""

import argparse
import json
import sys
import uuid
from collections.abc import Sequence
from typing import Any

from sqlalchemy.orm import Session, sessionmaker

from agnusmail.core.config import Settings, get_settings
from agnusmail.core.logging import configure_logging
from agnusmail.infrastructure.database.session import create_db_engine
from agnusmail.modules import models as _all_models  # noqa: F401  (resolves every FK)
from agnusmail.modules.audit.integrity import chain_owners, purge_expired, verify_user_chain


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m agnusmail.modules.audit", description="Audit chain maintenance."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify", help="verify audit hash chains")
    verify.add_argument("--user", type=uuid.UUID, action="append", help="only this user")
    purge = commands.add_parser("purge", help="purge events past the retention period")
    purge.add_argument("--user", type=uuid.UUID, action="append", help="only this user")
    purge.add_argument("--dry-run", action="store_true", help="run, then roll back")
    return parser


def _verify(factory: sessionmaker[Session], users: list[uuid.UUID] | None) -> dict[str, Any]:
    with factory() as session:
        owners = users if users is not None else chain_owners(session)
        reports = [verify_user_chain(session, owner) for owner in owners]
    return {
        "command": "verify",
        "ok": all(r.ok for r in reports),
        "chains": len(reports),
        "events": sum(r.checked for r in reports),
        "broken": [
            {"user_id": str(r.user_id), "reason": r.reason, "failed_seq": r.failed_seq}
            for r in reports
            if not r.ok
        ],
    }


def _purge(
    factory: sessionmaker[Session],
    retention_days: int,
    users: list[uuid.UUID] | None,
    dry_run: bool,
) -> dict[str, Any]:
    report = purge_expired(factory, retention_days=retention_days, users=users, dry_run=dry_run)
    return {
        "command": "purge",
        "ok": report.ok,
        "dry_run": dry_run,
        "retention_days": retention_days,
        "cutoff": report.cutoff.isoformat(),
        "users_purged": len(report.purged),
        "events_deleted": sum(p.deleted for p in report.purged),
        "broken": [str(u) for u in report.broken],
        "failed": [str(u) for u in report.failed],
    }


def main(
    argv: Sequence[str] | None = None,
    *,
    settings: Settings | None = None,
    factory: sessionmaker[Session] | None = None,
) -> int:
    args = _parser().parse_args(argv)
    settings = settings or get_settings()
    configure_logging(stream=sys.stderr)
    engine = None
    if factory is None:
        engine = create_db_engine(settings)
        factory = sessionmaker(bind=engine, expire_on_commit=False)
    try:
        if args.command == "verify":
            summary = _verify(factory, args.user)
        else:
            summary = _purge(factory, settings.audit_retention_days, args.user, args.dry_run)
    finally:
        if engine is not None:
            engine.dispose()
    print(json.dumps(summary, sort_keys=True))
    return 0 if summary["ok"] else 1
