"""Login helpers shared by API tests."""

from dataclasses import dataclass

from eth_account import Account
from eth_account.signers.local import LocalAccount
from fastapi.testclient import TestClient

from tests.unit.test_auth import build_message, sign


@dataclass(frozen=True)
class LoggedIn:
    user_id: str
    address: str
    account: LocalAccount  # test wallet: signs SIWE and EIP-712 attestations


def login(client: TestClient, account: LocalAccount | None = None) -> LoggedIn:
    """SIWE login on ``client`` (its cookie jar then holds the session)."""
    acct = account or Account.create()
    nonce = client.post("/v1/auth/siwe/nonce").json()["nonce"]
    response = client.post(
        "/v1/auth/siwe/verify", json=sign(build_message(acct.address, nonce), acct)
    )
    assert response.status_code == 200, response.text
    return LoggedIn(user_id=response.json()["user_id"], address=acct.address, account=acct)
