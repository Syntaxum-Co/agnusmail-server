"""PostgreSQL integration tests for the address registry."""

import secrets
import uuid
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import Engine, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.core.config import Settings
from agnusmail.core.exceptions import AgnusmailError
from agnusmail.infrastructure.database.session import create_db_engine
from agnusmail.infrastructure.database.transaction import run_sync_transaction
from agnusmail.modules import models as _all_models  # noqa: F401  (resolves every FK)
from agnusmail.modules.addresses.models import MailAddress
from agnusmail.modules.addresses.service import claim_address
from agnusmail.modules.audit.service import ActorContext
from agnusmail.modules.identity.models import User

pytestmark = pytest.mark.integration


@pytest.fixture
def engine() -> Iterator[Engine]:
    db_engine = create_db_engine(Settings(_env_file=None))  # type: ignore[call-arg]
    try:
        yield db_engine
    finally:
        db_engine.dispose()


@pytest.fixture
def factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False)


def new_user(factory: sessionmaker[Session]) -> uuid.UUID:
    with factory() as session, session.begin():
        user = User(ethereum_address="0x" + secrets.token_hex(20))
        session.add(user)
        session.flush()
        return user.id


def unique_domain() -> str:
    """Each test run gets its own domain: names are never released."""
    return f"t{secrets.token_hex(6)}.example.com"


def attempt(factory: sessionmaker[Session], user_id: uuid.UUID, name: str, domain: str) -> str:
    try:
        run_sync_transaction(
            factory, lambda s: claim_address(s, ActorContext(user_id=user_id), name, domain)
        )
    except AgnusmailError as exc:
        return exc.error_code
    return "ok"


def test_concurrent_lookalike_claims_have_a_single_winner(
    factory: sessionmaker[Session],
) -> None:
    domain = unique_domain()
    lookalikes = ["joaosilva", "joao.silva", "j0aosilva", "joao-silva", "joao_silva", "joaosiiva"]
    users = [new_user(factory) for _ in lookalikes]
    with ThreadPoolExecutor(max_workers=len(users)) as pool:
        results = list(
            pool.map(
                lambda pair: attempt(factory, pair[0], pair[1], domain),
                zip(users, lookalikes, strict=True),
            )
        )
    assert results.count("ok") == 1, results
    assert set(results) - {"ok"} <= {"ADDRESS_TAKEN", "CONFLICT"}
    with factory() as session:
        count = session.scalar(
            select(func.count()).select_from(MailAddress).where(MailAddress.domain == domain)
        )
    assert count == 1


def test_concurrent_claims_of_one_account_keep_one_address(
    factory: sessionmaker[Session],
) -> None:
    domain = unique_domain()
    owner = new_user(factory)
    names = [f"name{n}" for n in range(6)]
    with ThreadPoolExecutor(max_workers=len(names)) as pool:
        results = list(pool.map(lambda name: attempt(factory, owner, name, domain), names))
    assert results.count("ok") == 1, results
    assert set(results) - {"ok"} <= {"ADDRESS_LIMIT", "CONFLICT"}


@pytest.mark.parametrize("local_part", ["Upper", ".dot", "a..b", "bad!"])
def test_postgres_enforces_the_local_part_syntax(
    factory: sessionmaker[Session], local_part: str
) -> None:
    owner = new_user(factory)
    with pytest.raises(IntegrityError), factory() as session, session.begin():
        session.add(
            MailAddress(
                user_id=owner,
                local_part=local_part,
                canonical=local_part.lower(),
                domain=unique_domain(),
            )
        )


def test_concurrent_alias_claims_stop_at_the_limit(factory: sessionmaker[Session]) -> None:
    from agnusmail.modules.addresses.models import MAX_ALIASES, AddressKind

    domain = unique_domain()
    owner = new_user(factory)
    assert attempt(factory, owner, "primary", domain) == "ok"

    def alias(name: str) -> str:
        try:
            run_sync_transaction(
                factory,
                lambda s: claim_address(
                    s, ActorContext(user_id=owner), name, domain, AddressKind.ALIAS
                ),
            )
        except AgnusmailError as exc:
            return exc.error_code
        return "ok"

    names = [f"alias{n}" for n in range(MAX_ALIASES + 4)]
    with ThreadPoolExecutor(max_workers=len(names)) as pool:
        results = list(pool.map(alias, names))
    assert results.count("ok") == MAX_ALIASES, results
    with factory() as session:
        kinds = session.scalars(select(MailAddress.kind).where(MailAddress.user_id == owner)).all()
    assert sorted(kinds) == ["alias"] * MAX_ALIASES + ["primary"]


def test_postgres_allows_one_primary_per_account(factory: sessionmaker[Session]) -> None:
    domain = unique_domain()
    owner = new_user(factory)
    for index, kind in enumerate(("primary", "primary")):
        with factory() as session:
            session.add(
                MailAddress(
                    user_id=owner,
                    local_part=f"direct{index}x",
                    canonical=f"dlrect{index}x",
                    domain=domain,
                    status="active",
                    kind=kind,
                )
            )
            if index == 0:
                session.commit()
            else:
                with pytest.raises(IntegrityError):
                    session.commit()
