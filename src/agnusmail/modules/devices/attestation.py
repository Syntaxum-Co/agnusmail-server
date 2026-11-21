"""Wallet attestations over EIP-712 typed data (protocol v1 §4, 4.D.4).

The account's wallet signs a ``DeviceCertificate`` binding the v6 fingerprint of a
device's primary key to the account address, and may sign a ``DeviceRevocation``.
Anyone can verify these by recovering the signer; the server does it before trusting a
device, and senders do it again on their side (they do not have to trust the server).

Only EOA signatures (65 bytes, ``v`` in {27, 28}, low ``s`` per EIP-2) are accepted;
EIP-1271 contract wallets are deferred.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from eth_account import Account
from eth_account.messages import encode_typed_data

DOMAIN_NAME = "Agnusmail"
DOMAIN_VERSION = "1"
MAX_CERTIFICATE_VALIDITY = timedelta(days=400)
CLOCK_SKEW = timedelta(minutes=5)
# secp256k1 group order; signatures must use the lower half (EIP-2) to be canonical.
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

DOMAIN_FIELDS = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
]
DEVICE_CERTIFICATE_FIELDS = [
    {"name": "account", "type": "address"},
    {"name": "deviceFingerprint", "type": "bytes32"},
    {"name": "service", "type": "string"},
    {"name": "issuedAt", "type": "uint64"},
    {"name": "expiresAt", "type": "uint64"},
]
DEVICE_REVOCATION_FIELDS = [
    {"name": "account", "type": "address"},
    {"name": "deviceFingerprint", "type": "bytes32"},
    {"name": "service", "type": "string"},
    {"name": "revokedAt", "type": "uint64"},
]


class AttestationError(ValueError):
    """The wallet attestation is invalid. ``reason`` is a stable code."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class DeviceCertificateClaim:
    account: str  # 0x-address
    device_fingerprint: str  # 64 hex chars (v6 fingerprint of the primary key)
    service: str
    issued_at: int  # Unix seconds
    expires_at: int


@dataclass(frozen=True)
class DeviceRevocationClaim:
    account: str
    device_fingerprint: str
    service: str
    revoked_at: int


def eip712_domain(chain_id: int) -> dict[str, Any]:
    return {"name": DOMAIN_NAME, "version": DOMAIN_VERSION, "chainId": chain_id}


def device_certificate_typed_data(claim: DeviceCertificateClaim, chain_id: int) -> dict[str, Any]:
    """The full EIP-712 document a wallet signs (``eth_signTypedData_v4``)."""
    return {
        "types": {"EIP712Domain": DOMAIN_FIELDS, "DeviceCertificate": DEVICE_CERTIFICATE_FIELDS},
        "primaryType": "DeviceCertificate",
        "domain": eip712_domain(chain_id),
        "message": {
            "account": claim.account,
            "deviceFingerprint": "0x" + claim.device_fingerprint,
            "service": claim.service,
            "issuedAt": claim.issued_at,
            "expiresAt": claim.expires_at,
        },
    }


def device_revocation_typed_data(claim: DeviceRevocationClaim, chain_id: int) -> dict[str, Any]:
    return {
        "types": {"EIP712Domain": DOMAIN_FIELDS, "DeviceRevocation": DEVICE_REVOCATION_FIELDS},
        "primaryType": "DeviceRevocation",
        "domain": eip712_domain(chain_id),
        "message": {
            "account": claim.account,
            "deviceFingerprint": "0x" + claim.device_fingerprint,
            "service": claim.service,
            "revokedAt": claim.revoked_at,
        },
    }


def recover_signer(typed_data: dict[str, Any], signature: bytes) -> str:
    """Lowercase address that signed the typed data; canonical EOA signatures only."""
    if len(signature) != 65:
        raise AttestationError("signature_length")
    if signature[64] not in (27, 28):
        raise AttestationError("signature_v")
    if int.from_bytes(signature[32:64], "big") > SECP256K1_N // 2:
        raise AttestationError("signature_high_s")
    try:
        signable = encode_typed_data(full_message=typed_data)
        address: str = Account.recover_message(signable, signature=signature)
    except Exception as exc:  # malformed points, bad encodings
        raise AttestationError("signature_invalid") from exc
    return address.lower()


def verify_device_certificate(
    claim: DeviceCertificateClaim, signature: bytes, *, chain_id: int, now: datetime
) -> None:
    """Spec §4.3: signer is the account, times are sane and the certificate is current."""
    issued = datetime.fromtimestamp(claim.issued_at, tz=now.tzinfo)
    expires = datetime.fromtimestamp(claim.expires_at, tz=now.tzinfo)
    if issued > now + CLOCK_SKEW:
        raise AttestationError("issued_in_future")
    if expires <= now:
        raise AttestationError("expired")
    if expires <= issued or expires - issued > MAX_CERTIFICATE_VALIDITY:
        raise AttestationError("validity_period")
    signer = recover_signer(device_certificate_typed_data(claim, chain_id), signature)
    if signer != claim.account.lower():
        raise AttestationError("wrong_signer")


def verify_device_revocation(
    claim: DeviceRevocationClaim, signature: bytes, *, chain_id: int, now: datetime
) -> None:
    if datetime.fromtimestamp(claim.revoked_at, tz=now.tzinfo) > now + CLOCK_SKEW:
        raise AttestationError("revoked_in_future")
    signer = recover_signer(device_revocation_typed_data(claim, chain_id), signature)
    if signer != claim.account.lower():
        raise AttestationError("wrong_signer")


# --- Recovery key (protocol v1 §8.2) ----------------------------------------------------

RECOVERY_KEY_CERTIFICATE_FIELDS = [
    {"name": "account", "type": "address"},
    {"name": "recoveryFingerprint", "type": "bytes32"},
    {"name": "service", "type": "string"},
    {"name": "issuedAt", "type": "uint64"},
]


@dataclass(frozen=True)
class RecoveryKeyClaim:
    account: str
    recovery_fingerprint: str  # v6 fingerprint of the recovery certificate's primary key
    service: str
    issued_at: int


def recovery_key_typed_data(claim: RecoveryKeyClaim, chain_id: int) -> dict[str, Any]:
    return {
        "types": {
            "EIP712Domain": DOMAIN_FIELDS,
            "RecoveryKeyCertificate": RECOVERY_KEY_CERTIFICATE_FIELDS,
        },
        "primaryType": "RecoveryKeyCertificate",
        "domain": eip712_domain(chain_id),
        "message": {
            "account": claim.account,
            "recoveryFingerprint": "0x" + claim.recovery_fingerprint,
            "service": claim.service,
            "issuedAt": claim.issued_at,
        },
    }


def verify_recovery_key(
    claim: RecoveryKeyClaim, signature: bytes, *, chain_id: int, now: datetime
) -> None:
    if datetime.fromtimestamp(claim.issued_at, tz=now.tzinfo) > now + CLOCK_SKEW:
        raise AttestationError("issued_in_future")
    signer = recover_signer(recovery_key_typed_data(claim, chain_id), signature)
    if signer != claim.account.lower():
        raise AttestationError("wrong_signer")


# --- Account migration after a lost wallet (protocol v1 §8.5) --------------------

ACCOUNT_MIGRATION_FIELDS = [
    {"name": "oldAccount", "type": "address"},
    {"name": "newAccount", "type": "address"},
    {"name": "recoveryFingerprint", "type": "bytes32"},
    {"name": "service", "type": "string"},
    {"name": "issuedAt", "type": "uint64"},
]


@dataclass(frozen=True)
class MigrationAcceptanceClaim:
    old_account: str
    new_account: str
    recovery_fingerprint: str
    service: str
    issued_at: int


def migration_acceptance_typed_data(
    claim: MigrationAcceptanceClaim, chain_id: int
) -> dict[str, Any]:
    return {
        "types": {
            "EIP712Domain": DOMAIN_FIELDS,
            "AccountMigrationAcceptance": ACCOUNT_MIGRATION_FIELDS,
        },
        "primaryType": "AccountMigrationAcceptance",
        "domain": eip712_domain(chain_id),
        "message": {
            "oldAccount": claim.old_account,
            "newAccount": claim.new_account,
            "recoveryFingerprint": "0x" + claim.recovery_fingerprint,
            "service": claim.service,
            "issuedAt": claim.issued_at,
        },
    }


def verify_migration_acceptance(
    claim: MigrationAcceptanceClaim, signature: bytes, *, chain_id: int
) -> None:
    """The NEW wallet signed it: proves control of the destination account."""
    signer = recover_signer(migration_acceptance_typed_data(claim, chain_id), signature)
    if signer != claim.new_account.lower():
        raise AttestationError("wrong_signer")
