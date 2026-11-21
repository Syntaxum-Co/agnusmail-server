"""The encrypted backup without a session (protocol v1 §8.4).

Who lost the wallet must still reach the backup. The answer for an unknown account must
be indistinguishable from a real backup: same structure, stable across requests.
"""

import base64
import secrets
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from agnusmail.infrastructure.openpgp import check_recovery_backup, split_packets
from agnusmail.modules.recovery import fetch
from tests.unit.fakes import make_app, make_session_factory, make_settings
from tests.unit.test_messages import Person, person
from tests.unit.test_recovery import register_recovery

VECTOR = Path(__file__).resolve().parent.parent / "vectors" / "recovery_backup_openpgpjs.pgp"
FETCH = "/v1/recovery/backup/fetch"
DOMAIN = "mail.agnusmail.localhost"


@pytest.fixture
def factory() -> sessionmaker[Session]:
    return make_session_factory()


@pytest.fixture
def app(factory: sessionmaker[Session]) -> Any:
    return make_app(make_settings(rate_limit_auth_per_ip=1000), factory)[0]


@pytest.fixture
def owner(app: Any) -> Iterator[tuple[Person, str, bytes]]:
    """An account with an address, a recovery key and a stored backup."""
    p = person(app)
    name = "rc" + secrets.token_hex(4)
    assert p.client.post("/v1/addresses", json={"local_part": name}).status_code == 201
    register_recovery(p)
    blob = VECTOR.read_bytes()
    assert p.client.put("/v1/recovery/backup", json={"blob": base64.b64encode(blob).decode()})
    yield p, f"{name}@{DOMAIN}", blob
    p.client.close()


@pytest.fixture
def stranger(app: Any) -> Iterator[TestClient]:
    with TestClient(app, raise_server_exceptions=False) as client:  # no session at all
        yield client


def fetched(client: TestClient, account: str) -> bytes:
    response = client.post(FETCH, json={"account": account})
    assert response.status_code == 200, response.text
    assert set(response.json()) == {"blob"}  # no version or date that a decoy could not fake
    return base64.b64decode(response.json()["blob"])


def test_the_owner_gets_the_backup_without_a_session(
    owner: tuple[Person, str, bytes], stranger: TestClient
) -> None:
    person_, email, blob = owner
    assert fetched(stranger, person_.user.address) == blob
    assert fetched(stranger, person_.user.address.lower()) == blob
    assert fetched(stranger, email) == blob
    assert fetched(stranger, email.upper()) == blob


def test_unknown_accounts_get_a_stable_decoy_of_the_same_shape(
    owner: tuple[Person, str, bytes], stranger: TestClient
) -> None:
    _, _, real = owner
    for account in ("0x" + secrets.token_hex(20), f"nobody{secrets.token_hex(3)}@{DOMAIN}"):
        first = fetched(stranger, account)
        assert fetched(stranger, account) == first  # stable, like a real backup
        assert first != real
        assert len(first) == len(real)
        check_recovery_backup(first)  # parses as a real backup would
        real_packets, fake_packets = split_packets(real), split_packets(first)
        assert [len(p) for p in real_packets] == [len(p) for p in fake_packets]
        assert real_packets[0][:8] == fake_packets[0][:8]  # framing and algorithms
        assert real_packets[0][24:27] == fake_packets[0][24:27]  # Argon2 t, p, m
    assert fetched(stranger, "0x" + "1" * 40) != fetched(stranger, "0x" + "2" * 40)


def test_an_account_without_a_backup_also_gets_a_decoy(
    app: Any, owner: tuple[Person, str, bytes], stranger: TestClient
) -> None:
    other = person(app)
    blob = fetched(stranger, other.user.address)
    check_recovery_backup(blob)
    assert blob != owner[2]
    other.client.close()


def test_decoys_depend_on_the_server_secret(factory: sessionmaker[Session]) -> None:
    with factory() as session:
        a = fetch.decoy(session, b"secret-one" * 4, "0x" + "3" * 40)
        b = fetch.decoy(session, b"secret-two" * 4, "0x" + "3" * 40)
    assert a != b
    check_recovery_backup(a)  # built-in shape when no backup exists yet


def test_fetching_is_rate_limited(factory: sessionmaker[Session]) -> None:
    app = make_app(make_settings(rate_limit_auth_per_ip=2), factory)[0]
    with TestClient(app, raise_server_exceptions=False) as client:
        codes = [
            client.post(FETCH, json={"account": "0x" + "4" * 40}).status_code for _ in range(3)
        ]
    assert codes == [200, 200, 429]
