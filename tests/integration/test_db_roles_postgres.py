"""Owner vs runtime PostgreSQL roles (4.3.4).

The test database user (owner, superuser in CI) provisions a runtime role, then every
check runs over a connection AS that runtime role. Roles are cluster-wide: the role is
re-provisioned (idempotently) by each run.
"""

import secrets
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import Engine, create_engine, make_url, text
from sqlalchemy.exc import DBAPIError, OperationalError
from sqlalchemy.orm import sessionmaker

from agnusmail.core.config import Settings
from agnusmail.infrastructure.database.roles import (
    RoleProvisioningError,
    check_runtime_role,
    provision_runtime_role,
    runtime_role_problems,
)
from agnusmail.modules.audit.integrity import purge_user, verify_user_chain
from agnusmail.modules.audit.models import AuditEventType
from agnusmail.modules.audit.service import ActorContext, record_event
from agnusmail.modules.identity.models import User

pytestmark = pytest.mark.integration

ROLE = "agnusmail_app_it"


@pytest.fixture(scope="module")
def owner_engine() -> Iterator[Engine]:
    engine = create_engine(Settings(_env_file=None).database_url)  # type: ignore[call-arg]
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture(scope="module")
def runtime_password(owner_engine: Engine) -> str:
    password = secrets.token_urlsafe(24)
    with owner_engine.begin() as connection:
        provision_runtime_role(connection, ROLE, password)
    return password


def runtime_engine(owner: Engine, password: str) -> Engine:
    url = make_url(owner.url).set(username=ROLE, password=password)
    return create_engine(url)


@pytest.fixture
def runtime(owner_engine: Engine, runtime_password: str) -> Iterator[Engine]:
    engine = runtime_engine(owner_engine, runtime_password)
    try:
        yield engine
    finally:
        engine.dispose()


def test_runtime_role_has_no_dangerous_privileges(owner_engine: Engine, runtime: Engine) -> None:
    with owner_engine.connect() as connection:
        owner_problems = runtime_role_problems(connection)
    assert any(p.startswith("owns table") for p in owner_problems)
    with runtime.connect() as connection:
        assert runtime_role_problems(connection) == []
    with pytest.raises(RoleProvisioningError, match="too privileged"):
        check_runtime_role(owner_engine, strict=True)
    assert check_runtime_role(runtime, strict=True) == []


def test_runtime_role_serves_the_application(runtime: Engine) -> None:
    factory = sessionmaker(bind=runtime, expire_on_commit=False)
    with factory() as session, session.begin():
        user = User(ethereum_address="0x" + secrets.token_hex(20))
        session.add(user)
        session.flush()
        record_event(
            session, ActorContext(user_id=user.id), AuditEventType.KEY_REGISTERED, owner_id=user.id
        )
        user.last_login_at = datetime.now(UTC)
    with factory() as session:
        assert verify_user_chain(session, user.id).ok


@pytest.mark.parametrize(
    ("statement", "message"),
    [
        ("UPDATE audit_events SET details = '{}' WHERE false", "permission denied"),
        ("DELETE FROM audit_chain_heads WHERE false", "permission denied"),
        ("TRUNCATE audit_events", "permission denied"),
        ("DELETE FROM users WHERE false", "permission denied"),
        ("ALTER TABLE audit_events DISABLE TRIGGER ALL", "must be owner"),
        ("DROP TRIGGER audit_events_controlled_delete ON audit_events", "must be owner"),
        ("SET session_replication_role = replica", "permission denied"),
        ("CREATE TABLE intruder (id int)", "permission denied"),
        ("SELECT version_num FROM alembic_version", "permission denied"),
    ],
)
def test_runtime_role_cannot_bypass_the_audit_guards(
    runtime: Engine, statement: str, message: str
) -> None:
    with pytest.raises(DBAPIError) as caught, runtime.begin() as connection:
        connection.exec_driver_sql(statement)
    assert message in str(caught.value.orig)


def test_runtime_role_can_run_the_retention_purge(runtime: Engine) -> None:
    factory = sessionmaker(bind=runtime, expire_on_commit=False)
    old = datetime.now(UTC) - timedelta(days=400)
    with factory() as session, session.begin():
        user = User(ethereum_address="0x" + secrets.token_hex(20))
        session.add(user)
        session.flush()
        owner: uuid.UUID = user.id
        for _ in range(2):
            record_event(
                session,
                ActorContext(user_id=owner),
                AuditEventType.KEY_REGISTERED,
                owner_id=owner,
                now=old,
            )
    with factory() as session, session.begin():
        outcome = purge_user(session, owner, cutoff=datetime.now(UTC) - timedelta(days=365))
    assert outcome is not None and outcome.deleted == 2
    with factory() as session:
        assert verify_user_chain(session, owner).ok


def test_provisioning_is_idempotent_and_rotates_the_password(
    owner_engine: Engine, runtime_password: str
) -> None:
    new_password = secrets.token_urlsafe(24)
    with owner_engine.begin() as connection:
        assert provision_runtime_role(connection, ROLE, new_password) is False
    rotated = runtime_engine(owner_engine, new_password)
    with rotated.connect() as connection:
        assert connection.execute(text("SELECT current_user")).scalar_one() == ROLE
    rotated.dispose()
    stale = runtime_engine(owner_engine, runtime_password)
    with pytest.raises(OperationalError):
        stale.connect().close()
    stale.dispose()
    # Restore the module's password for the other tests.
    with owner_engine.begin() as connection:
        provision_runtime_role(connection, ROLE, runtime_password)


def test_provisioning_as_the_runtime_role_is_refused(runtime: Engine) -> None:
    with pytest.raises(RoleProvisioningError), runtime.begin() as connection:
        provision_runtime_role(connection, ROLE, None)


def test_password_is_stored_as_a_scram_verifier(owner_engine: Engine) -> None:
    with owner_engine.connect() as connection:
        stored = connection.execute(
            text("SELECT rolpassword FROM pg_authid WHERE rolname = :r"), {"r": ROLE}
        ).scalar_one()
    assert stored.startswith("SCRAM-SHA-256$")
