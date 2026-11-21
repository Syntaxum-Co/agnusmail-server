"""EIP-712 ``PasskeyRegistration``: the wallet approves a passkey for the account.

Same domain and signature rules as the device attestations (protocol v1 §4.1, §4.3). The
passkey is named by the SHA-256 of its WebAuthn credential id (fixed size).
"""

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from agnusmail.modules.devices.attestation import (
    DOMAIN_FIELDS,
    AttestationError,
    eip712_domain,
    recover_signer,
)

PASSKEY_REGISTRATION_FIELDS = [
    {"name": "account", "type": "address"},
    {"name": "credentialHash", "type": "bytes32"},
    {"name": "service", "type": "string"},
    {"name": "issuedAt", "type": "uint64"},
]
# The wallet approves a registration happening now; an old signature is not accepted.
MAX_AGE = timedelta(minutes=10)
CLOCK_SKEW = timedelta(minutes=5)


def credential_hash(credential_id: bytes) -> str:
    return hashlib.sha256(credential_id).hexdigest()


@dataclass(frozen=True)
class PasskeyRegistrationClaim:
    account: str
    credential_id: bytes
    service: str
    issued_at: int


def passkey_registration_typed_data(
    claim: PasskeyRegistrationClaim, chain_id: int
) -> dict[str, Any]:
    return {
        "types": {
            "EIP712Domain": DOMAIN_FIELDS,
            "PasskeyRegistration": PASSKEY_REGISTRATION_FIELDS,
        },
        "primaryType": "PasskeyRegistration",
        "domain": eip712_domain(chain_id),
        "message": {
            "account": claim.account,
            "credentialHash": "0x" + credential_hash(claim.credential_id),
            "service": claim.service,
            "issuedAt": claim.issued_at,
        },
    }


def verify_passkey_registration(
    claim: PasskeyRegistrationClaim, signature: bytes, *, chain_id: int, now: datetime
) -> None:
    issued = datetime.fromtimestamp(claim.issued_at, tz=now.tzinfo)
    if issued > now + CLOCK_SKEW:
        raise AttestationError("issued_in_future")
    if issued < now - MAX_AGE:
        raise AttestationError("too_old")
    signer = recover_signer(passkey_registration_typed_data(claim, chain_id), signature)
    if signer != claim.account.lower():
        raise AttestationError("wrong_signer")
