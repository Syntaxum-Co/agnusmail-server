"""Device API schemas. Request models are strict and forbid unknown fields."""

import unicodedata
import uuid
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator

from agnusmail.core.schemas import UtcDatetime
from agnusmail.modules.devices.models import DEVICE_NAME_MAX_LENGTH, REVOCATION_REASON_MAX_LENGTH


def clean_label(value: str) -> str:
    """Reject control/format/separator characters and surrounding whitespace.

    Labels are shown in UIs and audit history; invisible or bidirectional-control
    characters could be used to spoof them.
    """
    if value != value.strip():
        raise ValueError("must not start or end with whitespace")
    for char in value:
        category = unicodedata.category(char)
        if category.startswith("C") or category in ("Zl", "Zp"):
            raise ValueError("must not contain control or invisible formatting characters")
    return value


class DeviceCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    name: str = Field(min_length=1, max_length=DEVICE_NAME_MAX_LENGTH)

    @field_validator("name")
    @classmethod
    def _clean_name(cls, value: str) -> str:
        return clean_label(value)


# Signed as uint64, but turned into datetimes, which end at 9999-12-31T23:59:59Z: a later
# value used to escape as an unhandled error (500), even on routes without a session.
MAX_UNIX_SECONDS = 253402300799
UnixSeconds = Annotated[int, Field(ge=0, le=MAX_UNIX_SECONDS)]
WALLET_SIGNATURE_PATTERN = r"^0x[0-9a-fA-F]{130}$"


class WalletSignedCertificate(BaseModel):
    """EIP-712 DeviceCertificate fields the wallet signed (protocol v1 §4.2).

    ``account``, ``deviceFingerprint`` and ``service`` are not sent: the server fills
    them from the session's account, the device and its configuration, so a signature
    over anything else simply does not verify.
    """

    model_config = ConfigDict(extra="forbid", strict=True)

    issued_at: UnixSeconds
    expires_at: UnixSeconds
    signature: str = Field(pattern=WALLET_SIGNATURE_PATTERN)


class WalletSignedRevocation(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    revoked_at: UnixSeconds
    signature: str = Field(pattern=WALLET_SIGNATURE_PATTERN)


class DeviceRevoke(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    reason: str | None = Field(default=None, min_length=1, max_length=REVOCATION_REASON_MAX_LENGTH)
    wallet_revocation: WalletSignedRevocation | None = None

    @field_validator("reason")
    @classmethod
    def _clean_reason(cls, value: str | None) -> str | None:
        return None if value is None else clean_label(value)


class DeviceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    status: str
    created_at: UtcDatetime
    authorized_at: UtcDatetime | None
    revoked_at: UtcDatetime | None
    revocation_reason: str | None
    fingerprint: str | None
    certificate_expires_at: UtcDatetime | None


class DevicePage(BaseModel):
    items: list[DeviceOut]
    total: int
    limit: int
    offset: int
