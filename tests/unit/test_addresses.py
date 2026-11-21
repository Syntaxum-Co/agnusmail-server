"""Address registry name@domain."""

import time
import uuid
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.core.config import DEFAULT_MAIL_DOMAIN
from agnusmail.modules.addresses import rules
from agnusmail.modules.audit.models import AuditEvent
from agnusmail.modules.authentication import dependencies
from agnusmail.modules.identity.models import User, UserStatus
from agnusmail.testing.auth import LoggedIn, login
from agnusmail.testing.fakes import make_app, make_session_factory, make_settings

ADDRESSES = "/v1/addresses"
RESOLVE = "/v1/directory/addresses"
DOMAIN = DEFAULT_MAIL_DOMAIN


# --- rules ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("joao", "joao"),
        ("Joao.Silva", "joao.silva"),
        ("a-b_c.d9", "a-b_c.d9"),
        ("x" * 32, "x" * 32),
    ],
)
def test_valid_local_parts_are_lowercased(raw: str, expected: str) -> None:
    assert rules.normalize(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "ab",  # too short
        "x" * 33,  # too long
        ".joao",
        "joao.",
        "jo..ao",
        "jo.-ao",
        "jo ao",
        "jo+ao",
        "joão",  # non-ASCII
        "jоao",  # Cyrillic 'о' homoglyph
        "jo@ao",
        "",
    ],
)
def test_invalid_local_parts_are_rejected(raw: str) -> None:
    with pytest.raises(rules.InvalidLocalPartError):
        rules.normalize(raw)


@pytest.mark.parametrize(
    "variants",
    [
        ("joaosilva", "joao.silva", "joao_silva", "joao-silva", "j0aosilva"),
        ("modern", "modem"),  # rn -> m
        ("william", "wiiliam", "w1lliam", "vvilliam"),
    ],
)
def test_confusable_variants_share_one_canonical_form(variants: tuple[str, ...]) -> None:
    assert len({rules.canonical(v) for v in variants}) == 1


@pytest.mark.parametrize(
    "name",
    [
        "postmaster",
        "abuse",
        "admin",
        "adm1n",
        "no-reply",
        "mailer-daemon",
        "agnus",
        "agnus.team",
        "agnusmail-support",
        "r00t",
    ],
)
def test_reserved_names_and_their_lookalikes_are_blocked(name: str) -> None:
    with pytest.raises(rules.ReservedLocalPartError):
        rules.check_not_reserved(rules.normalize(name))


def test_ordinary_names_are_not_reserved() -> None:
    for name in ("maria", "adminho", "postal", "securityguy"):
        rules.check_not_reserved(name)


def test_mail_domain_must_be_a_lowercase_hostname_and_explicit_when_deployed() -> None:
    assert make_settings(mail_domain="mail.example.com").mail_domain == "mail.example.com"
    for bad in ("Mail.Example.com", "localhost", "exa_mple.com", "-a.com"):
        with pytest.raises(ValidationError):
            make_settings(mail_domain=bad)
    with pytest.raises(ValidationError, match="mail_domain"):
        make_settings(
            environment="staging",
            database_url="postgresql+psycopg://u:p@db/agnusmail?sslmode=require",
            force_https=True,
            siwe_domain="mail.example.com",
            siwe_uri="https://mail.example.com/login",
            trusted_proxies=["10.0.0.1"],
        )


# --- API -----------------------------------------------------------------------------


@pytest.fixture
def factory() -> sessionmaker[Session]:
    return make_session_factory()


@pytest.fixture
def client(factory: sessionmaker[Session]) -> Iterator[TestClient]:
    app, _ = make_app(session_factory=factory)
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client


@pytest.fixture
def user(client: TestClient) -> LoggedIn:
    return login(client)


def claim(client: TestClient, name: str) -> dict[str, object]:
    response = client.post(ADDRESSES, json={"local_part": name})
    assert response.status_code == 201, response.text
    return response.json()  # type: ignore[no-any-return]


def test_claim_list_and_resolve(
    client: TestClient, user: LoggedIn, factory: sessionmaker[Session]
) -> None:
    created = claim(client, "Maria.Souza")
    assert created["email"] == f"maria.souza@{DOMAIN}"
    assert created["status"] == "active"
    assert client.get(ADDRESSES).json()["items"] == [created]

    resolved = client.get(f"{RESOLVE}/MARIA.SOUZA@{DOMAIN.upper()}")
    assert resolved.status_code == 200
    assert resolved.json() == {"email": created["email"], "account": user.address.lower()}

    with factory() as session:
        event = session.scalars(
            select(AuditEvent).where(AuditEvent.event_type == "address.claimed")
        ).one()
        assert event.user_id == uuid.UUID(user.user_id)
        assert event.details["address"] == created["email"]


def test_one_permanent_address_per_account(client: TestClient, user: LoggedIn) -> None:
    claim(client, "first")
    second = client.post(ADDRESSES, json={"local_part": "second"})
    assert second.status_code == 409
    assert second.json()["error"]["code"] == "ADDRESS_LIMIT"


def test_lookalike_of_a_taken_name_is_refused(factory: sessionmaker[Session]) -> None:
    app, _ = make_app(session_factory=factory)
    with (
        TestClient(app, raise_server_exceptions=False) as alice,
        TestClient(app, raise_server_exceptions=False) as mallory,
    ):
        login(alice)
        login(mallory)
        claim(alice, "joaosilva")
        for lookalike in ("joao.silva", "j0aosilva", "JOAO_SILVA", "joaosiiva"):
            response = mallory.post(ADDRESSES, json={"local_part": lookalike})
            assert response.status_code == 409, lookalike
            assert response.json()["error"]["code"] == "ADDRESS_TAKEN"
        # Routing is exact: the lookalikes do not reach Alice either.
        assert mallory.get(f"{RESOLVE}/joao.silva@{DOMAIN}").status_code == 404


@pytest.mark.parametrize(
    ("name", "code", "status"),
    [
        ("postmaster", "ADDRESS_RESERVED", 409),
        ("agnus-help", "ADDRESS_RESERVED", 409),
        ("ab", "ADDRESS_INVALID", 422),
        ("joão", "ADDRESS_INVALID", 422),
    ],
)
def test_reserved_and_invalid_names(
    client: TestClient, user: LoggedIn, name: str, code: str, status: int
) -> None:
    response = client.post(ADDRESSES, json={"local_part": name})
    assert response.status_code == status
    assert response.json()["error"]["code"] == code


def test_claim_requires_a_recent_login(
    client: TestClient, user: LoggedIn, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Later:  # only the step-up clock moves; the session itself stays valid
        @staticmethod
        def time() -> float:
            return time.time() + 601  # default step-up window is 600 s

    monkeypatch.setattr(dependencies, "time", Later)
    response = client.post(ADDRESSES, json={"local_part": "latecomer"})
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "REAUTHENTICATION_REQUIRED"


def test_resolution_requires_a_session(client: TestClient) -> None:
    assert client.get(f"{RESOLVE}/someone@{DOMAIN}").status_code == 401


@pytest.mark.parametrize(
    "email",
    [
        f"nobody@{DOMAIN}",
        "maria@other.example.com",  # other domain
        "maria",  # no domain
        f"ma..ria@{DOMAIN}",  # invalid syntax
    ],
)
def test_unresolvable_addresses_are_404(client: TestClient, user: LoggedIn, email: str) -> None:
    claim(client, "maria")
    assert client.get(f"{RESOLVE}/{email}").status_code == 404


def test_suspended_accounts_do_not_resolve(
    client: TestClient, user: LoggedIn, factory: sessionmaker[Session]
) -> None:
    claim(client, "maria")
    with factory() as session, session.begin():
        account = session.get(User, uuid.UUID(user.user_id))
        assert account is not None
        account.status = UserStatus.SUSPENDED
    with factory() as session:
        assert session.get(User, uuid.UUID(user.user_id)) is not None
    other_app, _ = make_app(session_factory=factory)
    with TestClient(other_app, raise_server_exceptions=False) as other:
        login(other)
        assert other.get(f"{RESOLVE}/maria@{DOMAIN}").status_code == 404


def test_mass_assignment_is_rejected(client: TestClient, user: LoggedIn) -> None:
    response = client.post(ADDRESSES, json={"local_part": "maria", "domain": "evil.com"})
    assert response.status_code == 422


# --- aliases -------------------------------------------------------

ALIASES = f"{ADDRESSES}/aliases"


def alias(client: TestClient, name: str) -> dict[str, object]:
    response = client.post(ALIASES, json={"local_part": name})
    assert response.status_code == 201, response.text
    return response.json()  # type: ignore[no-any-return]


def test_aliases_resolve_to_the_same_account(
    client: TestClient, user: LoggedIn, factory: sessionmaker[Session]
) -> None:
    claim(client, "maria")
    created = alias(client, "Compras.Maria")
    assert (created["kind"], created["status"]) == ("alias", "active")
    resolved = client.get(f"{RESOLVE}/compras.maria@{DOMAIN}").json()
    assert resolved["account"] == user.address.lower()
    kinds = [a["kind"] for a in client.get(ADDRESSES).json()["items"]]
    assert kinds == ["primary", "alias"]
    with factory() as session:
        assert session.scalars(
            select(AuditEvent).where(AuditEvent.event_type == "address.alias_claimed")
        ).one()


def test_alias_needs_the_primary_first(client: TestClient, user: LoggedIn) -> None:
    response = client.post(ALIASES, json={"local_part": "early"})
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "PRIMARY_ADDRESS_REQUIRED"


def test_at_most_five_aliases_disabled_included(client: TestClient, user: LoggedIn) -> None:
    claim(client, "maria")
    created = [alias(client, f"extra{n}") for n in range(5)]
    client.post(f"{ADDRESSES}/{created[0]['id']}/disable")  # disabling frees nothing
    sixth = client.post(ALIASES, json={"local_part": "extra5"})
    assert sixth.status_code == 409
    assert sixth.json()["error"]["code"] == "ADDRESS_LIMIT"


def test_aliases_follow_the_name_rules(
    client: TestClient, user: LoggedIn, factory: sessionmaker[Session]
) -> None:
    claim(client, "maria")
    assert client.post(ALIASES, json={"local_part": "postmaster"}).status_code == 409
    assert client.post(ALIASES, json={"local_part": "agnusteam"}).status_code == 409
    assert client.post(ALIASES, json={"local_part": "m@ria"}).status_code == 422
    assert client.post(ALIASES, json={"local_part": "rnaria"}).status_code == 409  # = maria
    other_app, _ = make_app(session_factory=factory)
    with TestClient(other_app, raise_server_exceptions=False) as other:
        login(other)
        claim(other, "joao")
        taken = other.post(ALIASES, json={"local_part": "maria"})
        assert taken.status_code == 409
        assert taken.json()["error"]["code"] == "ADDRESS_TAKEN"


def test_disabled_alias_stops_resolving_and_can_come_back(
    client: TestClient, user: LoggedIn, factory: sessionmaker[Session]
) -> None:
    primary = claim(client, "maria")
    extra = alias(client, "shop")
    off = client.post(f"{ADDRESSES}/{extra['id']}/disable")
    assert off.json()["status"] == "disabled"
    assert client.get(f"{RESOLVE}/shop@{DOMAIN}").status_code == 404
    on = client.post(f"{ADDRESSES}/{extra['id']}/enable")
    assert on.json()["status"] == "active"
    assert client.get(f"{RESOLVE}/shop@{DOMAIN}").status_code == 200
    # The primary cannot be disabled.
    assert client.post(f"{ADDRESSES}/{primary['id']}/disable").status_code == 409
    with factory() as session:
        types = session.scalars(
            select(AuditEvent.event_type).where(AuditEvent.event_type.like("address.%abled"))
        ).all()
        assert sorted(types) == ["address.disabled", "address.enabled"]


def test_others_cannot_touch_an_alias(
    client: TestClient, user: LoggedIn, factory: sessionmaker[Session]
) -> None:
    claim(client, "maria")
    extra = alias(client, "shop")
    other_app, _ = make_app(session_factory=factory)
    with TestClient(other_app, raise_server_exceptions=False) as other:
        login(other)
        assert other.post(f"{ADDRESSES}/{extra['id']}/disable").status_code == 404
    assert client.get(f"{RESOLVE}/shop@{DOMAIN}").status_code == 200
