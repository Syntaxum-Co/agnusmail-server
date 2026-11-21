"""Outbound SMTP service entry point (protocol v1 §10) — NOT E2EE.

- ``python -m agnusmail.apps.smtp_outbound``: deliver the queue. Publishes its queue certificate
  before starting.
- ``python -m agnusmail.apps.smtp_outbound generate-key <path> [--if-missing]``: queue key file.
- ``python -m agnusmail.apps.smtp_outbound generate-dkim-key <path> [--if-missing]``: DKIM key.
- ``python -m agnusmail.apps.smtp_outbound dns-records``: the SPF, DKIM and DMARC records to
  publish for the mail domain.

It holds the backend's only decryption key (the queue key): the process
is made non-dumpable before reading it, swap must be off for the container, and it runs
as its own database role (``OUTBOUND_TABLE_PRIVILEGES``); outside the local environment
it refuses to start without any of that. SIGTERM/SIGINT finish the current round.
"""

import argparse
import signal
import sys
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.core.config import Settings, get_settings
from agnusmail.core.logging import configure_logging, get_logger
from agnusmail.infrastructure.database.roles import OUTBOUND_TABLE_PRIVILEGES, check_runtime_role
from agnusmail.infrastructure.database.session import create_db_engine
from agnusmail.infrastructure.metrics import start_metrics
from agnusmail.modules import models as _all_models  # noqa: F401  (resolves every FK)
from agnusmail.modules.inbound.keyfile import KeyFileError
from agnusmail.modules.inbound.process import REQUIRED, harden_process
from agnusmail.modules.outbound.delivery import DnsResolver, SmtpDelivery
from agnusmail.modules.outbound.dkim import (
    DkimKeyError,
    DkimSigner,
    create_dkim_key,
    dns_record,
    load_signer,
)
from agnusmail.modules.outbound.models import OutboundKey
from agnusmail.modules.outbound.queue_key import (
    QueueKey,
    QueueKeyError,
    create_queue_key,
    read_queue_key,
)
from agnusmail.modules.outbound.sender import OutboundSender

log = get_logger(__name__)


def register_queue_key(session: Session, key: QueueKey) -> bool:
    """Publish the queue certificate (idempotent). True when it was new."""
    exists = session.scalar(
        select(OutboundKey.id).where(OutboundKey.fingerprint == key.fingerprint)
    )
    if exists is not None:
        return False
    session.add(
        OutboundKey(
            fingerprint=key.fingerprint,
            encryption_fingerprint=key.encryption_fingerprint,
            material=key.certificate,
            expires_at=key.expires_at,
        )
    )
    session.flush()
    return True


def build_transport(settings: Settings) -> SmtpDelivery:
    relay = None
    if settings.outbound_relay:
        host, _, port = settings.outbound_relay.rpartition(":")
        relay = (host, int(port))
    return SmtpDelivery(
        hostname=settings.outbound_hostname or "localhost",
        resolver=DnsResolver(lifetime=settings.outbound_smtp_timeout_seconds),
        port=settings.outbound_smtp_port,
        require_tls=settings.outbound_require_tls,
        connect_timeout=settings.outbound_smtp_timeout_seconds,
        relay=relay,
    )


def startup_problem(settings: Settings, hardened: set[str]) -> str | None:
    """Why the service must not start (None: fine)."""
    deployed = settings.environment != "local"
    if deployed and not REQUIRED <= hardened:
        return "outbound_process_not_hardened"
    if settings.outbound_key_file is None:
        return "outbound_queue_key_missing"
    if settings.outbound_dkim_key_file is None:
        return "outbound_dkim_key_missing"
    if deployed and settings.outbound_hostname is None:
        return "outbound_hostname_missing"  # EHLO name (needs A/AAAA and PTR)
    return None


def load_keys(settings: Settings) -> tuple[list[QueueKey], DkimSigner]:
    assert settings.outbound_key_file is not None
    assert settings.outbound_dkim_key_file is not None
    keys = [read_queue_key(settings.outbound_key_file)]
    keys += [read_queue_key(path) for path in settings.outbound_previous_key_files]
    signer = load_signer(
        settings.outbound_dkim_key_file,
        domain=settings.mail_domain,
        selector=settings.outbound_dkim_selector,
    )
    return keys, signer


def serve(
    settings: Settings,
    sender: OutboundSender,
    stop: threading.Event,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> None:
    while not stop.is_set():
        try:
            busy = sender.run_once(clock())
        except Exception:  # database down, etc.: log and keep going
            log.exception("outbound_round_failed")
            busy = 0
        if not busy:
            stop.wait(settings.outbound_poll_seconds)


def run() -> int:
    hardened = harden_process()  # before the queue key or any message reaches memory
    settings = get_settings()
    configure_logging(debug=settings.environment == "local")
    problem = startup_problem(settings, hardened)
    if problem:
        log.error(problem)
        return 2
    try:
        keys, signer = load_keys(settings)
    except (KeyFileError, QueueKeyError, DkimKeyError, ValueError) as exc:
        log.error("outbound_keys_invalid", error=str(exc))
        return 2
    start_metrics(settings)
    engine = create_db_engine(settings)
    try:
        check_runtime_role(
            engine, strict=settings.environment != "local", allowed=OUTBOUND_TABLE_PRIVILEGES
        )
        factory = sessionmaker(bind=engine, expire_on_commit=False)
        with factory() as session, session.begin():
            if register_queue_key(session, keys[0]):
                log.info("outbound_queue_key_published", queue_fingerprint=keys[0].fingerprint)
        sender = OutboundSender(
            factory,
            keys=keys,
            signer=signer,
            transport=build_transport(settings),
            mail_domain=settings.mail_domain,
            batch_size=settings.outbound_batch_size,
            lease=timedelta(seconds=settings.outbound_lease_seconds),
        )
        stop = threading.Event()
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, lambda *_: stop.set())
        log.info("outbound_started", queue_fingerprint=keys[0].fingerprint)
        serve(settings, sender, stop)
    finally:
        engine.dispose()
    return 0


def _create(path: Path, if_missing: bool, create: Callable[[Path], object]) -> int:
    if if_missing and path.exists():
        return 0
    try:
        created = create(path)
    except FileExistsError:
        print(f"refusing to overwrite {path}", file=sys.stderr)
        return 1
    if isinstance(created, QueueKey):
        print(created.fingerprint)
    return 0


def dns_records(settings: Settings) -> int:
    """What to publish so receivers accept the mail (SPF, DKIM, DMARC; RFC 7208/6376/7489)."""
    if settings.outbound_dkim_key_file is None:
        print("AGNUSMAIL_OUTBOUND_DKIM_KEY_FILE is not set", file=sys.stderr)
        return 2
    domain = settings.mail_domain
    record = dns_record(settings.outbound_dkim_key_file.read_bytes())
    host = settings.outbound_hostname or "<outbound hostname>"
    print(f'{domain}. TXT "v=spf1 a:{host} -all"')
    print(f'{settings.outbound_dkim_selector}._domainkey.{domain}. TXT "{record}"')
    print(f'_dmarc.{domain}. TXT "v=DMARC1; p=reject; adkim=s; aspf=s"')
    print(f"; and a PTR for the outbound IP(s) resolving to {host}, which resolves back")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m agnusmail.apps.smtp_outbound")
    commands = parser.add_subparsers(dest="command")
    for name in ("generate-key", "generate-dkim-key"):
        command = commands.add_parser(name)
        command.add_argument("path", type=Path)
        command.add_argument("--if-missing", action="store_true")
    commands.add_parser("dns-records")
    args = parser.parse_args(argv)
    if args.command == "generate-key":
        return _create(args.path, args.if_missing, create_queue_key)
    if args.command == "generate-dkim-key":
        return _create(args.path, args.if_missing, create_dkim_key)
    if args.command == "dns-records":
        return dns_records(get_settings())
    return run()


if __name__ == "__main__":
    sys.exit(main())
