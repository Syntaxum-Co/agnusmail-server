"""Public key API schemas.

Key material travels as standard base64 (RFC 4648 §4) and must be canonical: no
whitespace, correct padding and zero padding bits, so each key has exactly one textual
representation.
"""

import base64
import binascii
import uuid
from datetime import UTC, datetime
from typing import Annotated

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field

from agnusmail.core.schemas import UtcDatetime
from agnusmail.modules.devices.models import Device
from agnusmail.modules.keys.models import (
    KEY_FORMAT_MAX_LENGTH,
    KEY_FORMAT_PATTERN,
    MATERIAL_HARD_LIMIT_BYTES,
    PublicKey,
)

MAX_BASE64_LENGTH = 4 * ((MATERIAL_HARD_LIMIT_BYTES + 2) // 3)


def decode_canonical_base64(value: object) -> bytes:
    if not isinstance(value, str):
        raise ValueError("must be a base64 string")
    if not value or len(value) > MAX_BASE64_LENGTH:
        raise ValueError(f"must be 1..{MAX_BASE64_LENGTH} base64 characters")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("invalid base64") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError("base64 must be canonical (padding and padding bits)")
    return decoded


Base64Material = Annotated[bytes, BeforeValidator(decode_canonical_base64)]


def encode_material(material: bytes) -> str:
    return base64.b64encode(material).decode("ascii")


class PublicKeyCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    # Protocol v1: "openpgp-v6/agnusmail-device-1" (other labels are rejected).
    format: str = Field(max_length=KEY_FORMAT_MAX_LENGTH, pattern=KEY_FORMAT_PATTERN)
    # Binary (not armored) transferable public key, OpenPGP v6.
    material: Base64Material
    # Binary v6 detached signature by the signing subkey over the registration statement
    # (protocol v1 §3.3): proof of possession.
    proof: Base64Material


class PublicKeyOut(BaseModel):
    id: uuid.UUID
    device_id: uuid.UUID
    version: int
    format: str
    material: str
    material_digest: str
    fingerprint: str | None
    encryption_fingerprint: str | None
    expires_at: UtcDatetime | None
    status: str
    created_at: UtcDatetime
    superseded_at: UtcDatetime | None
    revoked_at: UtcDatetime | None

    @classmethod
    def from_key(cls, key: PublicKey) -> "PublicKeyOut":
        return cls(
            id=key.id,
            device_id=key.device_id,
            version=key.version,
            format=key.format,
            material=encode_material(key.material),
            material_digest=key.material_digest,
            fingerprint=key.fingerprint,
            encryption_fingerprint=key.encryption_fingerprint,
            expires_at=key.expires_at,
            status=key.status,
            created_at=key.created_at,
            superseded_at=key.superseded_at,
            revoked_at=key.revoked_at,
        )


class PublicKeyPage(BaseModel):
    items: list[PublicKeyOut]
    total: int
    limit: int
    offset: int


def _unix(value: datetime) -> int:
    utc = value.replace(tzinfo=UTC) if value.tzinfo is None else value
    return int(utc.timestamp())


class WalletCertificateOut(BaseModel):
    """EIP-712 DeviceCertificate as signed (rebuild the typed data with the directory's
    ``address``, ``service``, ``chain_id`` and the key's ``fingerprint``)."""

    issued_at: int
    expires_at: int
    signature: str


class DirectoryKeyOut(BaseModel):
    """What other users see: no status history, no device names."""

    key_id: uuid.UUID
    device_id: uuid.UUID
    version: int
    format: str
    material: str
    material_digest: str
    fingerprint: str | None
    encryption_fingerprint: str | None
    expires_at: UtcDatetime | None
    created_at: UtcDatetime
    device_certificate: WalletCertificateOut

    @classmethod
    def from_entry(cls, key: PublicKey, device: Device) -> "DirectoryKeyOut":
        assert device.certificate_issued_at and device.certificate_expires_at
        assert device.certificate_signature
        return cls(
            key_id=key.id,
            device_id=key.device_id,
            version=key.version,
            format=key.format,
            material=encode_material(key.material),
            material_digest=key.material_digest,
            fingerprint=key.fingerprint,
            encryption_fingerprint=key.encryption_fingerprint,
            expires_at=key.expires_at,
            created_at=key.created_at,
            device_certificate=WalletCertificateOut(
                issued_at=_unix(device.certificate_issued_at),
                expires_at=_unix(device.certificate_expires_at),
                signature=device.certificate_signature,
            ),
        )


class WalletRevocationOut(BaseModel):
    """EIP-712 DeviceRevocation signed by the account's wallet."""

    device_fingerprint: str
    revoked_at: int
    signature: str

    @classmethod
    def from_device(cls, device: Device) -> "WalletRevocationOut":
        assert device.fingerprint and device.wallet_revoked_at
        return cls(
            device_fingerprint=device.fingerprint,
            revoked_at=_unix(device.wallet_revoked_at),
            signature=str(device.wallet_revocation_signature),
        )


class DirectoryOut(BaseModel):
    address: str
    # EIP-712 context to verify the wallet attestations (protocol v1 §4.1).
    service: str
    chain_id: int
    keys: list[DirectoryKeyOut]
    revocations: list[WalletRevocationOut]
    # Recovery certificate (spec §8.2): senders add a PKESK for its encryption subkey;
    # verify its RecoveryKeyCertificate against ``wallet_account``.
    recovery_key: dict[str, object] | None = None
    # Completed wallet migrations, oldest first (spec §8.5): device certificates signed by
    # an older wallet are valid only if issued before that wallet's migration.
    migrations: list[dict[str, object]] = []
