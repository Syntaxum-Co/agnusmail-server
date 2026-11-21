"""API helpers for device certificates (protocol v1 §3) shared by unit tests."""

import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_account.signers.local import LocalAccount
from fastapi.testclient import TestClient

from agnusmail.infrastructure.openpgp import PROTOCOL_KEY_FORMAT
from agnusmail.modules.devices.attestation import (
    DeviceCertificateClaim,
    DeviceRevocationClaim,
    device_certificate_typed_data,
    device_revocation_typed_data,
)
from agnusmail.modules.keys.policy import registration_statement
from agnusmail.testing.auth import LoggedIn
from agnusmail.testing.fakes import make_settings
from agnusmail.testing.openpgp import DeviceKeys, b64, new_device

DEVICES = "/v1/devices"
FORMAT = PROTOCOL_KEY_FORMAT
SERVICE = make_settings().siwe_domain


def key_payload(
    account: str,
    device: DeviceKeys | None = None,
    *,
    material: bytes | None = None,
    service: str = SERVICE,
) -> dict[str, str]:
    """A certificate (or a given version of it) with its proof of possession."""
    device = device or new_device()
    statement = registration_statement(service, account, device.fingerprint)
    return {
        "format": FORMAT,
        "material": b64(material or device.material),
        "proof": b64(device.sign(statement)),
    }


def next_version(device: DeviceKeys, step: int = 1) -> bytes:
    """A new version of the same certificate (same primary key, new self-signatures)."""
    return device.refreshed(datetime.now(UTC) + timedelta(days=300 + step))


def add_key(
    client: TestClient, device_id: str, account: str, device: DeviceKeys | None = None, **kw: Any
) -> dict[str, Any]:
    response = client.post(f"{DEVICES}/{device_id}/keys", json=key_payload(account, device, **kw))
    assert response.status_code == 201, response.text
    return response.json()  # type: ignore[no-any-return]


def wallet_certificate(
    wallet: LocalAccount,
    fingerprint: str,
    *,
    issued_at: int | None = None,
    expires_at: int | None = None,
    service: str = SERVICE,
    chain_id: int = 1,
) -> dict[str, Any]:
    """EIP-712 DeviceCertificate signed by the test wallet (protocol v1 §4)."""
    now = int(time.time())
    issued = now - 60 if issued_at is None else issued_at
    expires = now + 300 * 86400 if expires_at is None else expires_at
    claim = DeviceCertificateClaim(wallet.address, fingerprint, service, issued, expires)
    typed = device_certificate_typed_data(claim, chain_id)
    signed = Account.sign_message(encode_typed_data(full_message=typed), private_key=wallet.key)
    return {
        "issued_at": issued,
        "expires_at": expires,
        "signature": "0x" + bytes(signed.signature).hex(),
    }


def wallet_revocation(
    wallet: LocalAccount, fingerprint: str, *, revoked_at: int | None = None, chain_id: int = 1
) -> dict[str, Any]:
    revoked = int(time.time()) if revoked_at is None else revoked_at
    claim = DeviceRevocationClaim(wallet.address, fingerprint, SERVICE, revoked)
    typed = device_revocation_typed_data(claim, chain_id)
    signed = Account.sign_message(encode_typed_data(full_message=typed), private_key=wallet.key)
    return {"revoked_at": revoked, "signature": "0x" + bytes(signed.signature).hex()}


@dataclass
class Onboarded:
    device_id: str
    keys: DeviceKeys
    key: dict[str, Any]


def onboard(
    client: TestClient,
    user: LoggedIn,
    *,
    authorize: bool = True,
    keys: DeviceKeys | None = None,
    name: str = "device",
) -> Onboarded:
    """Register a device, publish its OpenPGP certificate and (optionally) authorize it
    with the wallet's EIP-712 DeviceCertificate — the real client flow."""
    keys = keys or new_device()
    device_id: str = client.post(DEVICES, json={"name": name}).json()["id"]
    key = add_key(client, device_id, user.address, keys)
    if authorize:
        response = client.post(
            f"{DEVICES}/{device_id}/authorize",
            json=wallet_certificate(user.account, keys.fingerprint),
        )
        assert response.status_code == 200, response.text
    return Onboarded(device_id, keys, key)
