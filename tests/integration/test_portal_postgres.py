"""Secure portal on PostgreSQL (protocol v1 §11).

The whole path with real PostgreSQL and Redis: the sender creates a portal message, the
notice leaves through the outbound service (its own role) to a test MTA with the link,
the recipient opens it with the token from that e-mail, replies, and the sender reads
the reply. Then the database's own limits and the purge.
"""

import base64
import re
import secrets
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pysequoia
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.apps.smtp_outbound.__main__ import register_queue_key
from agnusmail.core.config import Settings
from agnusmail.infrastructure.database.session import create_db_engine
from agnusmail.infrastructure.openpgp import split_packets
from agnusmail.modules import models as _all_models  # noqa: F401  (resolves every FK)
from agnusmail.modules.outbound.dkim import DkimSigner, generate_dkim_key
from agnusmail.modules.outbound.models import OutboundMessage, OutboundStatus
from agnusmail.modules.outbound.queue_key import generate_queue_key, load_queue_key
from agnusmail.modules.portal.models import PortalMessage
from agnusmail.modules.portal.service import purge_expired
from tests.integration.test_inbound_no_plaintext import found_in_database
from tests.integration.test_messages_postgres import live_person
from tests.integration.test_outbound_postgres import sender_for
from tests.outbound_helpers import TestMta
from tests.unit.test_messages import Person
from tests.unit.test_portal import PLAINTEXT, envelope

pytestmark = pytest.mark.integration

BASE_URL = "https://app.example.com/portal"


@pytest.fixture(scope="module")
def settings_env() -> Settings:
    return Settings(_env_file=None, portal_base_url=BASE_URL)  # type: ignore[call-arg]


@pytest.fixture(scope="module")
def engine(settings_env: Settings) -> Iterator[Engine]:
    db_engine = create_db_engine(settings_env)
    try:
        yield db_engine
    finally:
        db_engine.dispose()


@pytest.fixture
def alice(settings_env: Settings, engine: Engine) -> Iterator[Person]:
    person = live_person(settings_env, sessionmaker(bind=engine, expire_on_commit=False))
    name = "pt" + secrets.token_hex(6)
    assert person.client.post("/v1/addresses", json={"local_part": name}).status_code == 201
    yield person
    person.client.__exit__(None, None, None)


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def test_notice_link_access_and_reply(
    settings_env: Settings, engine: Engine, alice: Person
) -> None:
    with engine.begin() as connection:  # settle queued rows left by earlier runs
        connection.execute(
            update(OutboundMessage)
            .where(OutboundMessage.status == OutboundStatus.QUEUED)
            .values(status=OutboundStatus.EXPIRED, payload=None, finished_at=datetime.now(UTC))
        )
    key = load_queue_key(generate_queue_key(), now=datetime.now(UTC))
    with sessionmaker(bind=engine)() as session, session.begin():
        register_queue_key(session, key)
    signer = DkimSigner(settings_env.mail_domain, "agnus1", generate_dkim_key())

    created = alice.client.post(
        "/v1/portal/messages",
        json={
            "version": 1,
            "message_id": secrets.token_hex(16),
            "recipients": ["friend@example.org"],
            "expires_in_days": 2,
            "envelope": b64(envelope(alice)),
        },
    )
    assert created.status_code == 201, created.text
    portal_id = created.json()["id"]

    mta = TestMta()
    mta.start()
    try:
        sender_for(engine, key, signer, mta, settings_env).run_once(datetime.now(UTC))
    finally:
        mta.stop()
    [notice] = mta.recorder.received
    assert notice.recipients == ["friend@example.org"]
    match = re.search(rb"https://app\.example\.com/portal#([A-Za-z0-9_-]{43})", notice.content)
    assert match is not None
    token = match.group(1).decode()
    assert b"TEST-ONLY" not in notice.content  # the message never travels in the notice
    assert found_in_database(engine, token) == []  # only its hash is stored

    from agnusmail.apps.api.main import create_app

    app = create_app(settings_env, session_factory=sessionmaker(bind=engine))
    with TestClient(app, raise_server_exceptions=False) as browser:
        opened = browser.post("/v1/portal/access", json={"token": token})
        assert opened.status_code == 200, opened.text
        directory = browser.post("/v1/portal/keys", json={"token": token}).json()
        entries = list(directory["keys"]) + (
            [directory["recovery_key"]] if directory.get("recovery_key") else []
        )
        certs = [pysequoia.Cert.from_bytes(base64.b64decode(k["material"])) for k in entries]
        *pkesks, body = split_packets(
            pysequoia.encrypt(b"TEST-ONLY re", recipients=certs, armor=False)
        )
        replied = browser.post(
            "/v1/portal/replies",
            json={
                "token": token,
                "version": 1,
                "pkesks": [b64(p) for p in pkesks],
                "body": b64(body),
            },
        )
        assert replied.status_code == 201, replied.text

    inbox = alice.client.get("/v1/messages", params={"folder": "inbox"}).json()["items"]
    assert [m["origin"] for m in inbox] == ["portal"]
    own = alice.client.get(f"/v1/portal/messages/{portal_id}").json()
    copy = pysequoia.decrypt(
        decryptor=alice.keys.tsk.decryptor(), bytes=base64.b64decode(own["envelope"])
    )
    assert bytes(copy.bytes or b"") == PLAINTEXT
    assert own["recipients"][0]["replies"] == 1


def test_database_limits_and_purge(engine: Engine, alice: Person) -> None:
    user_id = uuid.UUID(alice.user.user_id)
    now = datetime.now(UTC)
    with Session(engine) as session, pytest.raises(IntegrityError):
        session.add(
            PortalMessage(
                sender_id=user_id,
                client_message_id=secrets.token_hex(16),
                envelope=b"abc",
                size=3,
                expires_at=now + timedelta(days=31),
                created_at=now,
            )
        )
        session.commit()
    with Session(engine) as session, session.begin():
        session.add(
            PortalMessage(
                sender_id=user_id,
                client_message_id=secrets.token_hex(16),
                envelope=b"abc",
                size=3,
                expires_at=now + timedelta(days=1),
                created_at=now,
            )
        )
    with Session(engine) as session, session.begin():
        assert purge_expired(session, now + timedelta(days=1)) >= 1
