"""Address API schemas."""

import uuid

from pydantic import BaseModel, ConfigDict, Field

from agnusmail.core.schemas import UtcDatetime
from agnusmail.modules.addresses.models import MailAddress


class AddressClaim(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    # Full validation happens in rules.normalize (clear error messages, one place).
    local_part: str = Field(min_length=1, max_length=64)


class AddressOut(BaseModel):
    id: uuid.UUID
    email: str
    local_part: str
    domain: str
    kind: str  # "primary" or "alias"
    status: str  # "active", "disabled" (aliases) or "retired"
    created_at: UtcDatetime

    @classmethod
    def from_address(cls, address: MailAddress) -> "AddressOut":
        return cls(
            id=address.id,
            email=address.email,
            local_part=address.local_part,
            domain=address.domain,
            kind=address.kind,
            status=address.status,
            created_at=address.created_at,
        )


class AddressList(BaseModel):
    items: list[AddressOut]


class ResolvedAddress(BaseModel):
    """Where to fetch keys next: ``GET /v1/keys/{account}``."""

    email: str
    account: str
