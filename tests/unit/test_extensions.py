"""Extension points: what an extension can add, and what it cannot change."""

import uuid
from datetime import datetime
from typing import Any

import pytest
from fastapi import APIRouter, Request
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from agnusmail.core.exceptions import AgnusmailError
from agnusmail.extensions import Extension, ExtensionError, Extensions, from_environment, load
from agnusmail.infrastructure.database.roles import RUNTIME_TABLE_PRIVILEGES
from agnusmail.modules.admin.service import ActionInvalidError, Context, Kind, changes_for
from agnusmail.modules.admin.service import validate as validate_action
from agnusmail.modules.audit.models import AuditEventTypeName
from agnusmail.modules.audit.service import record_event
from agnusmail.modules.identity.models import User
from agnusmail.modules.jobs.handlers import JOBS, SCHEDULE, Periodic
from agnusmail.modules.jobs.queue import JobSpec
from agnusmail.modules.quotas.policy import QuotaPolicy
from agnusmail.testing.auth import login
from agnusmail.testing.fakes import make_app, make_session_factory, make_settings

# --- a small example extension -------------------------------------------------------

router = APIRouter()
created_accounts: list[uuid.UUID] = []


@router.get("/example/ping")
async def ping() -> dict[str, str]:
    return {"pong": "yes"}


@router.post("/example/webhook")
async def webhook(request: Request) -> dict[str, int]:
    return {"received": len(await request.body())}


class NotThisMonthError(AgnusmailError):
    status_code = 402
    message = "no paid period"
    code = "EXAMPLE_NOT_PAID"


class ExamplePolicy(QuotaPolicy):
    def quota_bytes_for(self, session: Session, user_id: uuid.UUID, now: datetime) -> int:
        return 123_456

    def growth_refusal(
        self, session: Session, user_id: uuid.UUID, now: datetime
    ) -> AgnusmailError | None:
        return NotThisMonthError()


def remember(session: Session, user: User, now: datetime) -> None:
    created_accounts.append(user.id)


def tick(*_: Any) -> None:
    return None


def act(*_: Any) -> dict[str, Any]:
    return {}


EXAMPLE = Extension(
    name="example",
    routers=(router,),
    raw_body_paths=frozenset({"/v1/example/webhook"}),
    quota_policy=lambda settings: ExamplePolicy(quota_bytes=settings.storage_quota_bytes),
    on_account_created=remember,
    jobs=(JobSpec("example.tick", tick),),
    schedule=(Periodic("example.tick", SCHEDULE[0].every),),
    admin_actions={"example_action": Kind({"account": lambda v: isinstance(v, str)}, act)},
    admin_credentials=frozenset({"example_api_key"}),
    table_privileges={"runtime": {"example_items": ("SELECT", "INSERT")}},
)
NOT_AN_EXTENSION = object()
REFERENCE = "tests.unit.test_extensions:EXAMPLE"


# --- loading ---------------------------------------------------------------------------


def test_load_by_reference() -> None:
    assert load([REFERENCE]).items == (EXAMPLE,)
    environment = {"AGNUSMAIL_EXTENSIONS": f'["{REFERENCE}"]'}
    assert from_environment(environment).items == (EXAMPLE,)
    assert from_environment({}).items == ()


@pytest.mark.parametrize(
    "references",
    [
        ["tests.unit.test_extensions"],  # no attribute
        ["tests.unit.test_extensions:EXAMPLE; rm -rf /"],  # not an identifier
        ["tests.unit.does_not_exist:EXAMPLE"],
        ["tests.unit.test_extensions:NOT_AN_EXTENSION"],
        [REFERENCE, REFERENCE],  # listed twice
    ],
)
def test_bad_references_stop_the_process(references: list[str]) -> None:
    with pytest.raises(ExtensionError):
        load(references)


def test_settings_carry_the_references() -> None:
    settings = make_settings(extensions=[REFERENCE])
    assert settings.extensions == [REFERENCE]


# --- privileges -----------------------------------------------------------------------


def test_extensions_only_add_their_own_tables() -> None:
    merged = Extensions((EXAMPLE,)).privileges("runtime", RUNTIME_TABLE_PRIVILEGES)
    assert merged["example_items"] == ("SELECT", "INSERT")
    assert {k: v for k, v in merged.items() if k != "example_items"} == RUNTIME_TABLE_PRIVILEGES


@pytest.mark.parametrize(
    "privileges",
    [
        {"runtime": {"users": ("SELECT", "UPDATE", "DELETE")}},  # a built-in table
        {"runtime": {"example_items": ("TRUNCATE",)}},  # not a DML privilege
        {"runtime": {"example_items": ()}},
    ],
)
def test_extensions_cannot_widen_or_invent_privileges(privileges: Any) -> None:
    sneaky = Extension(name="sneaky", table_privileges=privileges)
    with pytest.raises(ExtensionError):
        Extensions((sneaky,)).privileges("runtime", RUNTIME_TABLE_PRIVILEGES)


def test_unknown_roles_are_refused() -> None:
    with pytest.raises(ExtensionError):
        Extensions().privileges("superuser", {})


# --- the API --------------------------------------------------------------------------


def test_api_mounts_the_extension() -> None:
    created_accounts.clear()
    app, _ = make_app(extensions=Extensions((EXAMPLE,)))
    with TestClient(app, raise_server_exceptions=False) as client:
        assert client.get("/v1/example/ping").json() == {"pong": "yes"}
        # Only the declared path skips the JSON requirement.
        raw = client.post(
            "/v1/example/webhook", content=b"a=1", headers={"content-type": "text/plain"}
        )
        assert raw.json() == {"received": 3}

        user = login(client)
        login(client, user.account)  # a second login does not create it again
        assert [str(i) for i in created_accounts] == [user.user_id]

        usage = client.get("/v1/usage").json()
        assert usage["quota_bytes"] == 123_456


def test_extension_policy_can_refuse_growth() -> None:
    factory = make_session_factory()
    policy = ExamplePolicy(quota_bytes=10)
    with factory() as session, session.begin():
        user = User(ethereum_address="0x" + "cd" * 20)
        session.add(user)
        session.flush()
        now = datetime.now()
        with pytest.raises(NotThisMonthError):
            policy.require_space(session, user.id, 1, now)
        assert not policy.accepts(session, user.id, 0, now)


def test_two_quota_policies_are_ambiguous() -> None:
    other = Extension(name="other", quota_policy=EXAMPLE.quota_policy)
    with pytest.raises(ExtensionError):
        Extensions((EXAMPLE, other)).quota_policy(make_settings())


# --- worker and admin -----------------------------------------------------------------


def test_jobs_and_schedule_are_added() -> None:
    extensions = Extensions((EXAMPLE,))
    assert [spec.kind for spec in extensions.jobs(JOBS)][-1] == "example.tick"
    assert extensions.schedule(SCHEDULE)[-1].kind == "example.tick"


def test_admin_actions_and_credentials_are_added() -> None:
    changes = changes_for(Extensions((EXAMPLE,)))
    ctx = Context(QuotaPolicy(quota_bytes=1), "mail.example.com", changes=changes)
    assert validate_action("example_action", {"account": "x"}, ctx) == {"account": "x"}
    assert validate_action("record_rotation", {"credential": "example_api_key"}, ctx)
    with pytest.raises(ActionInvalidError):  # built-in context: unknown
        validate_action("example_action", {"account": "x"}, Context(QuotaPolicy(1), "m.example"))


def test_admin_actions_cannot_replace_built_in_ones() -> None:
    hijack = Extension(name="hijack", admin_actions={"suspend_account": Kind({}, act)})
    with pytest.raises(ExtensionError):
        changes_for(Extensions((hijack,)))


# --- audit event types ----------------------------------------------------------------


def test_audit_event_types_must_be_registered() -> None:
    """Built-in types work; an extension's type needs its row in audit_event_types."""
    factory = make_session_factory()
    with factory() as session, session.begin():
        user = User(ethereum_address="0x" + "ef" * 20)
        session.add(user)
        session.flush()
        record_event(session, None, "auth.logout", owner_id=user.id)
    with factory() as session, pytest.raises(IntegrityError), session.begin():
        record_event(session, None, "example.unregistered", owner_id=user.id)
    with factory() as session, session.begin():
        session.add(AuditEventTypeName(name="example.registered"))
        session.flush()
        record_event(session, None, "example.registered", owner_id=user.id)
