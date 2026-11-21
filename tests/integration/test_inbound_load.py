"""Load on the inbound gateway: concurrent connections, real PostgreSQL + Redis.

Every message must be accepted exactly once and stored for the right account; nothing
lost, nothing duplicated. Size: AGNUSMAIL_LOAD_MESSAGES (default 60, enough for CI;
raise it for a longer run). Prints the measured throughput.
"""

import os
import secrets
import smtplib
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

import pytest
import redis
from sqlalchemy import func, select
from sqlalchemy.orm import sessionmaker

from agnusmail.core.config import Settings
from agnusmail.infrastructure.database.session import create_db_engine
from agnusmail.infrastructure.openpgp import generate_gateway_key, load_gateway_key
from agnusmail.infrastructure.redis.rate_limit import RateLimiter
from agnusmail.modules import models as _all_models  # noqa: F401  (resolves every FK)
from agnusmail.modules.inbound.delivery import GatewayContext, register_gateway_key
from agnusmail.modules.inbound.smtp import InboundHandler
from agnusmail.modules.messages.models import MailboxEntry, Message, MessageOrigin
from tests.integration.test_inbound_no_plaintext import close_on_gateway_loop
from tests.integration.test_messages_postgres import live_person
from tests.unit.test_inbound import Gateway

pytestmark = pytest.mark.integration

MESSAGES = int(os.environ.get("AGNUSMAIL_LOAD_MESSAGES", "60"))
CONNECTIONS = 12
BODY = ("TEST-ONLY load line " * 40 + "\r\n").encode() * 25  # ~20 KiB; SMTP lines < 998


def test_concurrent_delivery_loses_and_duplicates_nothing() -> None:
    settings = Settings(  # type: ignore[call-arg]
        _env_file=None,
        inbound_max_connections_per_ip=CONNECTIONS * 2,
        inbound_messages_per_ip_per_hour=MESSAGES * 10,
        # Real Redis keeps the API's login limits across runs; this test logs in 3 times.
        rate_limit_auth_per_ip=10_000,
        rate_limit_per_ip=100_000,
    )
    engine = create_db_engine(settings)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    people = [live_person(settings, factory) for _ in range(3)]
    key = load_gateway_key(generate_gateway_key(), now=datetime.now(UTC))
    with factory() as session, session.begin():
        register_gateway_key(session, key)
    redis_client = redis.asyncio.Redis.from_url(settings.redis_url)
    handler = InboundHandler(
        factory,
        GatewayContext.from_settings(settings, key),
        settings,
        None,
        RateLimiter(redis_client),
    )
    gateway = Gateway(handler, settings)
    gateway.start()
    try:
        addresses = []
        for person in people:
            name = "ld" + secrets.token_hex(6)
            assert person.client.post("/v1/addresses", json={"local_part": name}).status_code == 201
            addresses.append(f"{name}@{settings.mail_domain}")
        tag = secrets.token_hex(4)

        def send(index: int) -> int:
            target = addresses[index % len(addresses)]
            message = f"Subject: load {tag} {index}\r\nTo: {target}\r\n\r\n".encode() + BODY
            with smtplib.SMTP(gateway.hostname, gateway.port, timeout=120) as client:
                client.ehlo("mx.example.org")
                client.mail("someone@example.org")
                client.rcpt(target)
                code, _ = client.data(message)
            return code

        started = time.monotonic()
        with ThreadPoolExecutor(max_workers=CONNECTIONS) as pool:
            codes = list(pool.map(send, range(MESSAGES)))
        elapsed = time.monotonic() - started
        print(
            f"\ninbound load: {MESSAGES} messages, {CONNECTIONS} connections, "
            f"{elapsed:.1f}s, {MESSAGES / elapsed:.1f} msg/s"
        )
        assert codes == [250] * MESSAGES

        with factory() as session:
            for index, person in enumerate(people):
                received = session.scalar(
                    select(func.count())
                    .select_from(MailboxEntry)
                    .join(Message, Message.id == MailboxEntry.message_id)
                    .where(
                        MailboxEntry.user_id == uuid.UUID(person.user.user_id),
                        Message.origin == MessageOrigin.EXTERNAL,
                    )
                )
                expected = len(range(index, MESSAGES, len(people)))
                assert received == expected, (index, received, expected)
    finally:
        close_on_gateway_loop(gateway, redis_client)
        gateway.stop()
        for person in people:
            person.client.__exit__(None, None, None)
        engine.dispose()
