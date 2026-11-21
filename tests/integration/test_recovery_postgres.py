"""Recovery on PostgreSQL + Redis: constraints of migration 0013 and the
complete migration flow, including the worker job and session revocation."""

import secrets
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from eth_account import Account
from sqlalchemy import Engine, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from agnusmail.core.config import Settings
from agnusmail.infrastructure.database.session import create_db_engine
from agnusmail.modules import models as _all_models  # noqa: F401  (resolves every FK)
from agnusmail.modules.identity.models import User
from agnusmail.modules.jobs.handlers import complete_migrations
from agnusmail.modules.jobs.queue import JobContext
from agnusmail.modules.recovery.models import AccountMigration, RecoveryBackup, RecoveryKey
from tests.integration.test_messages_postgres import live_person
from tests.unit.test_messages import PLAINTEXT, compose, open_message
from tests.unit.test_recovery import migration_payload, register_recovery

pytestmark = pytest.mark.integration


@pytest.fixture
def settings_env() -> Settings:
    return Settings(_env_file=None)  # type: ignore[call-arg]


@pytest.fixture
def engine(settings_env: Settings) -> Iterator[Engine]:
    db_engine = create_db_engine(settings_env)
    try:
        yield db_engine
    finally:
        db_engine.dispose()


def test_recovery_and_migration_on_postgres(settings_env: Settings, engine: Engine) -> None:
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    alice, bob = live_person(settings_env, factory), live_person(settings_env, factory)
    try:
        recovery = register_recovery(bob)
        sent = alice.client.post("/v1/messages", json=compose(alice, [bob]))
        assert sent.status_code == 201, sent.text
        assert open_message(bob, sent.json()["id"], alice) == PLAINTEXT

        new_wallet = Account.create()
        payload = migration_payload(bob, recovery, new_wallet)
        requested = alice.client.post("/v1/recovery/migrations", json=payload)
        assert requested.status_code == 202, requested.text
        again = alice.client.post("/v1/recovery/migrations", json=payload)
        assert again.status_code == 409  # one pending migration per account

        # A week passes (moved back in the database), then the worker job runs: bob's
        # account moves to the new wallet and his sessions end.
        week = timedelta(days=8)
        with factory() as session, session.begin():
            session.execute(
                update(AccountMigration)
                .where(AccountMigration.id == uuid.UUID(requested.json()["id"]))
                .values(
                    requested_at=AccountMigration.requested_at - week,
                    effective_at=AccountMigration.effective_at - week,
                )
            )
        complete_migrations(JobContext(factory=factory, settings=settings_env), {})
        with factory() as session:
            user = session.get(User, uuid.UUID(bob.user.user_id))
            assert user is not None and user.ethereum_address == new_wallet.address.lower()
        assert bob.client.get("/v1/recovery/key").status_code == 401  # session ended
        evidence = alice.client.get(f"/v1/keys/{new_wallet.address}").json()["migrations"]
        assert len(evidence) == 1
    finally:
        alice.client.__exit__(None, None, None)
        bob.client.__exit__(None, None, None)


def recovery_key_row(user_id: uuid.UUID, **override: object) -> RecoveryKey:
    now = datetime.now(UTC)
    values: dict[str, object] = {
        "user_id": user_id,
        "material": b"m",
        "fingerprint": secrets.token_hex(32),
        "signing_fingerprint": secrets.token_hex(32),
        "encryption_fingerprint": secrets.token_hex(32),
        "expires_at": now + timedelta(days=365),
        "wallet_account": "0x" + "00" * 20,
        "wallet_signature": "0x" + "00" * 65,
        "wallet_issued_at": now,
    }
    return RecoveryKey(**(values | override))


def test_postgres_enforces_recovery_constraints(engine: Engine) -> None:
    factory = sessionmaker(bind=engine)
    with factory() as session, session.begin():
        user = User(ethereum_address="0x" + secrets.token_hex(20))
        session.add(user)
        session.flush()
        key = recovery_key_row(user.id)
        session.add(key)
        session.flush()
        user_id, key_id = user.id, key.id
        session.add(RecoveryBackup(user_id=user_id, recovery_key_id=key_id, version=1, blob=b"x"))
    for values in (
        {"version": 1, "blob": b"y"},  # duplicate version
        {"version": 0, "blob": b"y"},  # versions start at 1
        {"version": 2, "blob": b"y" * (64 * 1024 + 1)},  # over 64 KiB
    ):
        with pytest.raises(IntegrityError), factory() as session, session.begin():
            session.add(RecoveryBackup(user_id=user_id, recovery_key_id=key_id, **values))
    with pytest.raises(IntegrityError), factory() as session, session.begin():
        session.add(recovery_key_row(user_id))  # a second active key
    with pytest.raises(IntegrityError), factory() as session, session.begin():
        session.add(recovery_key_row(user_id, status="replaced"))  # without replaced_at
