"""EIP-712 wallet attestations of devices (protocol v1 §4)."""

import dataclasses
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils.crypto import keccak

from agnusmail.modules.devices.attestation import (
    SECP256K1_N,
    AttestationError,
    DeviceCertificateClaim,
    DeviceRevocationClaim,
    device_certificate_typed_data,
    device_revocation_typed_data,
    recover_signer,
    verify_device_certificate,
    verify_device_revocation,
)

# Well-known throwaway test key (web3.py documentation); never holds funds.
TEST_KEY = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
WALLET = Account.from_key(TEST_KEY)
FPR = "ab" * 32
NOW = datetime(2026, 11, 12, 12, 0, tzinfo=UTC)
CLAIM = DeviceCertificateClaim(
    account=WALLET.address,
    device_fingerprint=FPR,
    service="mail.example.com",
    issued_at=int(NOW.timestamp()),
    expires_at=int((NOW + timedelta(days=365)).timestamp()),
)
CHAIN_ID = 1


def sign(typed: dict[str, object], key: str = TEST_KEY) -> bytes:
    signed = Account.sign_message(encode_typed_data(full_message=typed), private_key=key)
    return bytes(signed.signature)


def manual_digest(claim: DeviceCertificateClaim, chain_id: int) -> bytes:
    """EIP-712 hash computed by hand (independent of eth_account's encoder)."""
    domain_type = b"EIP712Domain(string name,string version,uint256 chainId)"
    cert_type = (
        b"DeviceCertificate(address account,bytes32 deviceFingerprint,string service,"
        b"uint64 issuedAt,uint64 expiresAt)"
    )
    domain = keccak(
        keccak(domain_type) + keccak(b"Agnusmail") + keccak(b"1") + chain_id.to_bytes(32, "big")
    )
    struct = keccak(
        keccak(cert_type)
        + bytes(12)
        + bytes.fromhex(claim.account[2:])
        + bytes.fromhex(claim.device_fingerprint)
        + keccak(claim.service.encode())
        + claim.issued_at.to_bytes(32, "big")
        + claim.expires_at.to_bytes(32, "big")
    )
    return keccak(b"\x19\x01" + domain + struct)


def test_digest_matches_an_independent_eip712_encoding() -> None:
    signable = encode_typed_data(full_message=device_certificate_typed_data(CLAIM, CHAIN_ID))
    library = keccak(b"\x19" + signable.version + signable.header + signable.body)
    assert library == manual_digest(CLAIM, CHAIN_ID)


def test_published_vector() -> None:
    """docs/specs/protocol-v1.md §14 (deterministic RFC 6979 signature)."""
    typed = device_certificate_typed_data(CLAIM, CHAIN_ID)
    signature = sign(typed)
    assert WALLET.address == "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23"
    assert manual_digest(CLAIM, CHAIN_ID).hex() == VECTOR_DIGEST
    assert signature.hex() == VECTOR_SIGNATURE


def test_valid_certificate_verifies() -> None:
    signature = sign(device_certificate_typed_data(CLAIM, CHAIN_ID))
    verify_device_certificate(CLAIM, signature, chain_id=CHAIN_ID, now=NOW)
    lower = dataclasses.replace(CLAIM, account=CLAIM.account.lower())
    verify_device_certificate(lower, signature, chain_id=CHAIN_ID, now=NOW)


def failure(claim: DeviceCertificateClaim, signature: bytes, **kwargs: object) -> str:
    params: dict[str, object] = {"chain_id": CHAIN_ID, "now": NOW, **kwargs}
    with pytest.raises(AttestationError) as caught:
        verify_device_certificate(claim, signature, **params)  # type: ignore[arg-type]
    return caught.value.reason


def test_tampered_or_foreign_certificates_fail() -> None:
    signature = sign(device_certificate_typed_data(CLAIM, CHAIN_ID))
    other_wallet = Account.create()
    by_other = sign(device_certificate_typed_data(CLAIM, CHAIN_ID), other_wallet.key.hex())
    assert failure(CLAIM, by_other) == "wrong_signer"
    for change in (
        {"device_fingerprint": "cd" * 32},
        {"service": "evil.example.com"},
        {"account": other_wallet.address},
        {"expires_at": CLAIM.expires_at + 1},
    ):
        assert failure(dataclasses.replace(CLAIM, **change), signature) == "wrong_signer"
    assert failure(CLAIM, signature, chain_id=5) == "wrong_signer"  # other chain


def test_signature_encoding_rules() -> None:
    signature = sign(device_certificate_typed_data(CLAIM, CHAIN_ID))
    r, s, v = signature[:32], int.from_bytes(signature[32:64], "big"), signature[64]
    high_s = r + (SECP256K1_N - s).to_bytes(32, "big") + bytes([55 - v])  # same point, high s
    assert failure(CLAIM, high_s) == "signature_high_s"
    assert failure(CLAIM, signature[:64] + bytes([v - 27])) == "signature_v"
    assert failure(CLAIM, signature[:64]) == "signature_length"


def test_time_rules() -> None:
    def signed(**change: Any) -> tuple[DeviceCertificateClaim, bytes]:
        claim = dataclasses.replace(CLAIM, **change)
        return claim, sign(device_certificate_typed_data(claim, CHAIN_ID))

    later = int((NOW + timedelta(hours=1)).timestamp())
    assert failure(*signed(issued_at=later)) == "issued_in_future"
    assert failure(*signed(expires_at=CLAIM.issued_at - 1)) == "expired"
    too_long = int((NOW + timedelta(days=401)).timestamp())
    assert failure(*signed(expires_at=too_long)) == "validity_period"
    claim, signature = signed()
    assert failure(claim, signature, now=NOW + timedelta(days=366)) == "expired"


def test_revocation_attestation() -> None:
    claim = DeviceRevocationClaim(WALLET.address, FPR, "mail.example.com", CLAIM.issued_at)
    signature = sign(device_revocation_typed_data(claim, CHAIN_ID))
    verify_device_revocation(claim, signature, chain_id=CHAIN_ID, now=NOW)
    with pytest.raises(AttestationError):
        verify_device_revocation(
            dataclasses.replace(claim, device_fingerprint="cd" * 32),
            signature,
            chain_id=CHAIN_ID,
            now=NOW,
        )
    # A certificate signature is not a revocation (different primary type).
    cert_signature = sign(device_certificate_typed_data(CLAIM, CHAIN_ID))
    with pytest.raises(AttestationError):
        verify_device_revocation(claim, cert_signature, chain_id=CHAIN_ID, now=NOW)


def test_recover_signer_rejects_garbage() -> None:
    typed = device_certificate_typed_data(CLAIM, CHAIN_ID)
    with pytest.raises(AttestationError):
        recover_signer(typed, bytes(64) + b"\x1b")


VECTOR_DIGEST = "680b5a9f31b67dd6648434cd9199d8eb40c0d91aff76c505480f2cb40b95e4e5"
VECTOR_SIGNATURE = (
    "a220cadc66928f9a9fd5a63a153ba93d96c4dc6b5baad686f3f63ab97819177458b303b554476884d36d"
    "6887e935524732476f60342713ae8ceda1336c0e0f351b"
)
