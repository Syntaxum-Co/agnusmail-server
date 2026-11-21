"""SIWE logins with throwaway wallets, as a client would do them."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_account.signers.local import LocalAccount
from fastapi.testclient import TestClient

DOMAIN = "app.agnusmail"


def build_message(
    address: str,
    nonce: str,
    *,
    domain: str = DOMAIN,
    uri: str = "https://app.agnusmail/login",
    chain_id: str = "1",
    issued: datetime | None = None,
    expiration: datetime | None = None,
    timestamp_format: str = "%Y-%m-%dT%H:%M:%SZ",
) -> str:
    issued = issued or datetime.now(UTC)
    expiration = expiration or issued + timedelta(minutes=10)
    return (
        f"{domain} wants you to sign in with your Ethereum account:\n"
        f"{address}\n"
        "\n"
        "Sign in to Agnusmail.\n"
        "\n"
        f"URI: {uri}\n"
        "Version: 1\n"
        f"Chain ID: {chain_id}\n"
        f"Nonce: {nonce}\n"
        f"Issued At: {issued.strftime(timestamp_format)}\n"
        f"Expiration Time: {expiration.strftime(timestamp_format)}"
    )


def sign(message: str, account: LocalAccount | None = None) -> dict[str, str]:
    acct = account or Account.create()
    signed = acct.sign_message(encode_defunct(text=message))
    return {"message": message, "signature": signed.signature.hex()}


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
