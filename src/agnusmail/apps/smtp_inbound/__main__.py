"""Inbound SMTP gateway entry point.

- ``python -m agnusmail.apps.smtp_inbound``: serve. Requires the signing key
  (``AGNUSMAIL_INBOUND_SIGNING_KEY_FILE``); publishes its certificate before listening.
- ``python -m agnusmail.apps.smtp_inbound generate-key <path> [--if-missing]``: create a signing
  key file (mode 0600, never overwritten) and print its fingerprint.

A separate process from the API. Messages stay in memory: the process is made
non-dumpable before accepting connections (``modules/inbound/process.py``); swap must be
off for the container (see the compose files). Runs as its own database role
(``GATEWAY_TABLE_PRIVILEGES``); outside the local environment it refuses to start with
any privilege beyond that.
SIGTERM/SIGINT stop accepting new connections and let open transactions finish.
"""

import argparse
import asyncio
import signal
import sys
from pathlib import Path

from sqlalchemy.orm import Session, sessionmaker

from agnusmail.core.config import Settings, get_settings
from agnusmail.core.logging import configure_logging, get_logger
from agnusmail.infrastructure.database.roles import (
    GATEWAY_TABLE_PRIVILEGES,
    check_runtime_role,
)
from agnusmail.infrastructure.database.session import create_db_engine
from agnusmail.infrastructure.metrics import start_metrics
from agnusmail.infrastructure.openpgp import GatewayKey
from agnusmail.infrastructure.redis.client import RedisClient
from agnusmail.infrastructure.redis.rate_limit import RateLimiter
from agnusmail.modules import models as _all_models  # noqa: F401  (resolves every FK)
from agnusmail.modules.inbound.antispam import RspamdScanner
from agnusmail.modules.inbound.delivery import GatewayContext, register_gateway_key
from agnusmail.modules.inbound.keyfile import (
    KeyFileError,
    check_private_file,
    create_signing_key,
    read_signing_key,
)
from agnusmail.modules.inbound.process import REQUIRED, harden_process
from agnusmail.modules.inbound.smtp import InboundHandler, build_smtp, build_tls_context

log = get_logger(__name__)


def build_scanner(settings: Settings) -> RspamdScanner | None:
    if settings.inbound_rspamd_url is None:
        return None
    return RspamdScanner(settings.inbound_rspamd_url, settings.inbound_rspamd_timeout_seconds)


async def serve(settings: Settings, factory: "sessionmaker[Session]", key: GatewayKey) -> None:
    ctx = GatewayContext.from_settings(settings, key)
    redis = RedisClient(settings)
    redis.create_pool()
    rates = RateLimiter(redis.client())
    handler = InboundHandler(factory, ctx, settings, build_scanner(settings), rates)
    tls = None
    if settings.inbound_tls_cert_file and settings.inbound_tls_key_file:
        check_private_file(settings.inbound_tls_key_file)
        tls = build_tls_context(settings.inbound_tls_cert_file, settings.inbound_tls_key_file)
    loop = asyncio.get_running_loop()
    server = await loop.create_server(
        lambda: build_smtp(handler, settings, tls),
        host=settings.inbound_smtp_host,
        port=settings.inbound_smtp_port,
    )
    stop = asyncio.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    log.info(
        "inbound_smtp_listening",
        port=settings.inbound_smtp_port,
        gateway_fingerprint=key.fingerprint,
    )
    await stop.wait()
    server.close()
    await server.wait_closed()
    await redis.dispose()


def generate_key(path: Path, *, if_missing: bool) -> int:
    if if_missing and path.exists():
        return 0
    try:
        key = create_signing_key(path)
    except FileExistsError:
        print(f"refusing to overwrite {path}", file=sys.stderr)
        return 1
    print(key.fingerprint)
    return 0


def run() -> int:
    hardened = harden_process()  # before any message can reach memory
    settings = get_settings()
    configure_logging(debug=settings.environment == "local")
    if settings.environment != "local" and not REQUIRED <= hardened:
        log.error("inbound_process_not_hardened", missing=sorted(REQUIRED - hardened))
        return 2
    if settings.inbound_rspamd_url is None and settings.environment != "local":
        log.error("inbound_antispam_missing")  # antispam runs before encryption
        return 2
    if settings.environment != "local" and not (
        settings.inbound_tls_cert_file and settings.inbound_tls_key_file
    ):
        log.error("inbound_tls_missing")  # STARTTLS must be offered
        return 2
    if settings.inbound_proxy_protocol and not settings.inbound_trusted_proxies:
        log.error("inbound_proxy_without_trusted_proxies")
        return 2
    if settings.inbound_signing_key_file is None:
        log.error("inbound_signing_key_missing")
        return 2
    try:
        key = read_signing_key(settings.inbound_signing_key_file)
    except (KeyFileError, ValueError) as exc:
        log.error("inbound_signing_key_invalid", error=str(exc))
        return 2
    start_metrics(settings)
    engine = create_db_engine(settings)
    try:
        check_runtime_role(
            engine, strict=settings.environment != "local", allowed=GATEWAY_TABLE_PRIVILEGES
        )
        factory = sessionmaker(bind=engine, expire_on_commit=False)
        with factory() as session, session.begin():
            if register_gateway_key(session, key):
                log.info("inbound_signing_key_published", gateway_fingerprint=key.fingerprint)
        asyncio.run(serve(settings, factory, key))
    finally:
        engine.dispose()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m agnusmail.apps.smtp_inbound")
    commands = parser.add_subparsers(dest="command")
    generate = commands.add_parser("generate-key", help="create a gateway signing key file")
    generate.add_argument("path", type=Path)
    generate.add_argument("--if-missing", action="store_true")
    args = parser.parse_args(argv)
    if args.command == "generate-key":
        return generate_key(args.path, if_missing=args.if_missing)
    return run()


if __name__ == "__main__":
    sys.exit(main())
