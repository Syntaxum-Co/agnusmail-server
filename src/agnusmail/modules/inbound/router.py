"""Public routes of the inbound gateway (protocol v1 §9).

- ``GET /v1/gateway/keys``: every signing certificate the gateway has used, oldest
  first. Clients verify the signature of external messages against this list. Public:
  no session (only public certificates).
"""

from datetime import datetime

from fastapi import APIRouter
from pydantic import BaseModel
from sqlalchemy import select

from agnusmail.core.schemas import UtcDatetime
from agnusmail.infrastructure.database.transaction import run_in_transaction
from agnusmail.modules.authentication.dependencies import DbSessionFactory
from agnusmail.modules.inbound.models import GatewayKey
from agnusmail.modules.keys.schemas import encode_material

router = APIRouter(prefix="/gateway", tags=["gateway"])


class GatewayKeyOut(BaseModel):
    fingerprint: str
    material: str  # base64 of the binary v6 certificate
    expires_at: UtcDatetime
    created_at: UtcDatetime


class GatewayKeyList(BaseModel):
    items: list[GatewayKeyOut]


def _out(row: GatewayKey) -> GatewayKeyOut:
    expires: datetime = row.expires_at
    return GatewayKeyOut(
        fingerprint=row.fingerprint,
        material=encode_material(row.material),
        expires_at=expires,
        created_at=row.created_at,
    )


@router.get("/keys")
async def gateway_keys(db: DbSessionFactory) -> GatewayKeyList:
    return await run_in_transaction(
        db,
        lambda s: GatewayKeyList(
            items=[_out(r) for r in s.scalars(select(GatewayKey).order_by(GatewayKey.created_at))]
        ),
    )
