"""No plaintext of external mail persists .

A random marker goes in the envelope sender, Subject and body of messages sent through
the gateway (in-process, real PostgreSQL + Redis, and Rspamd when configured). Then every
column of every table and every Redis key and value is searched for it — as text and as
the hex form PostgreSQL uses for bytea. Delivered, failed and refused messages alike.
The container-level proof (files, logs, Rspamd, swap) is ``scripts/inbound-no-persistence.sh``.
"""

import asyncio
import os
import secrets
import smtplib
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
import redis
from sqlalchemy import Engine, text
from sqlalchemy.orm import sessionmaker

from agnusmail.core.config import Settings
from agnusmail.infrastructure.database.session import create_db_engine
from agnusmail.infrastructure.openpgp import generate_gateway_key, load_gateway_key
from agnusmail.infrastructure.redis.rate_limit import RateLimiter
from agnusmail.modules import models as _all_models  # noqa: F401  (resolves every FK)
from agnusmail.modules.inbound import delivery
from agnusmail.modules.inbound.antispam import RspamdScanner
from agnusmail.modules.inbound.delivery import GatewayContext, register_gateway_key
from agnusmail.modules.inbound.smtp import InboundHandler
from tests.integration.test_messages_postgres import live_person
from tests.unit.test_inbound import Gateway

pytestmark = pytest.mark.integration

RSPAMD_URL = os.environ.get("AGNUSMAIL_TEST_RSPAMD_URL")


@pytest.fixture(scope="module")
def settings_env() -> Settings:
    return Settings(_env_file=None)  # type: ignore[call-arg]


@pytest.fixture(scope="module")
def engine(settings_env: Settings) -> Iterator[Engine]:
    db_engine = create_db_engine(settings_env)
    try:
        yield db_engine
    finally:
        db_engine.dispose()


def close_on_gateway_loop(gateway: Gateway, client: Any) -> None:
    """Close an async Redis client on the loop it was used in (the gateway's thread).
    Left to the garbage collector, it would warn during whatever test runs next."""
    asyncio.run_coroutine_threadsafe(client.aclose(), gateway.loop).result(timeout=10)


def found_in_database(engine: Engine, marker: str) -> list[str]:
    needles = {"text": marker, "hex": marker.encode().hex()}
    hits: list[str] = []
    with engine.connect() as connection:
        tables = connection.execute(
            text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
        ).scalars()
        for table in tables:
            for kind, needle in needles.items():
                # Table names come from pg_tables, not from input.
                query = f'SELECT count(*) FROM "{table}" AS row WHERE strpos(row::text, :n) > 0'  # noqa: S608
                count = connection.execute(
                    text(query),
                    {"n": needle},
                ).scalar_one()
                if count:
                    hits.append(f"{table} ({kind})")
    return hits


def found_in_redis(url: str, marker: str) -> list[str]:
    client = redis.Redis.from_url(url)
    needle = marker.encode()
    hits: list[str] = []
    try:
        for key in client.scan_iter(count=1000):
            kind = client.type(key)
            values: list[Any]
            if kind == b"string":
                values = [client.get(key)]
            elif kind == b"hash":
                values = [*client.hgetall(key).items()]
            elif kind == b"zset":
                values = list(client.zrange(key, 0, -1))
            elif kind == b"list":
                values = list(client.lrange(key, 0, -1))
            elif kind == b"set":
                values = list(client.smembers(key))
            else:
                values = []
            if needle in key or any(needle in repr(v).encode() for v in values):
                hits.append(key.decode(errors="replace"))
    finally:
        client.close()
    return hits


def test_nothing_in_clear_after_delivery_failure_or_refusal(
    settings_env: Settings, engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = "testonly" + secrets.token_hex(12)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    alice = live_person(settings_env, factory)
    key = load_gateway_key(generate_gateway_key(), now=datetime.now(UTC))
    with factory() as session, session.begin():
        register_gateway_key(session, key)
    redis_client = redis.asyncio.Redis.from_url(settings_env.redis_url)
    scanner = RspamdScanner(RSPAMD_URL, 60) if RSPAMD_URL else None
    handler = InboundHandler(
        factory,
        GatewayContext.from_settings(settings_env, key),
        settings_env,
        scanner,
        RateLimiter(redis_client),
    )
    gateway = Gateway(handler, settings_env)
    gateway.start()
    try:
        name = "np" + secrets.token_hex(6)
        assert alice.client.post("/v1/addresses", json={"local_part": name}).status_code == 201
        address = f"{name}@{settings_env.mail_domain}"
        message = (
            f"From: Someone <{marker}@example.org>\r\nTo: {address}\r\n"
            f"Subject: {marker} subject\r\nMessage-ID: <{marker}@example.org>\r\n"
            f"Date: Fri, 13 Nov 2026 10:00:00 +0000\r\n\r\n{marker} body line\r\n"
        ).encode()

        def send() -> int:
            with smtplib.SMTP(gateway.hostname, gateway.port, timeout=60) as client:
                client.ehlo("mx.example.org")
                client.mail(f"{marker}@example.org")
                client.rcpt(address)
                code, _ = client.data(message)
            return code

        assert send() in (250, 550)  # 550 only if Rspamd rejects it as spam

        def broken(_plaintext: bytes, _certs: list[bytes], _signer: Any = None) -> Any:
            raise RuntimeError(marker)  # the failure itself quotes the content

        monkeypatch.setattr(delivery, "encrypt_to_certificates", broken)
        assert send() in (451, 550)
    finally:
        close_on_gateway_loop(gateway, redis_client)
        gateway.stop()
        alice.client.__exit__(None, None, None)

    # The searches work: they find what is stored on purpose (controls).
    assert "mail_addresses (text)" in found_in_database(engine, name)
    assert found_in_redis(settings_env.redis_url, "inbound:messages:127.0.0.1")
    # ...and nothing of the message, in any table or key.
    assert found_in_database(engine, marker) == []
    assert found_in_redis(settings_env.redis_url, marker) == []
