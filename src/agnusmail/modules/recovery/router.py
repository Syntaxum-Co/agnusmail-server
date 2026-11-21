"""Recovery API (/v1/recovery, protocol v1 §8).

- ``POST /v1/recovery/key``: recovery certificate + proof + wallet RecoveryKeyCertificate.
- ``GET /v1/recovery/key``: the account's active recovery certificate.
- ``PUT /v1/recovery/backup``: a new version of the client-encrypted backup.
- ``GET /v1/recovery/backup``: the latest backup (decrypted only on the client).
- ``POST /v1/recovery/migrations`` (no session), ``GET``, ``…/{id}/cancel``: moving
  the account to a new wallet after losing the old one (spec §8.5).
"""

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from agnusmail.core.config import Settings
from agnusmail.core.exceptions import ResourceNotFoundError
from agnusmail.core.schemas import UtcDatetime
from agnusmail.infrastructure.database.transaction import run_in_transaction
from agnusmail.modules.authentication.dependencies import (
    CurrentSession,
    DbSessionFactory,
    actor_context,
    auth_rate_limit,
)
from agnusmail.modules.devices.schemas import WALLET_SIGNATURE_PATTERN, UnixSeconds
from agnusmail.modules.keys.schemas import Base64Material, encode_material
from agnusmail.modules.recovery import fetch, migration, service
from agnusmail.modules.recovery.models import AccountMigration, RecoveryBackup, RecoveryKey

router = APIRouter(prefix="/recovery", tags=["recovery"])


class WalletCertificateIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    issued_at: UnixSeconds
    signature: str = Field(pattern=WALLET_SIGNATURE_PATTERN)


class RecoveryKeyIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    format: str = Field(pattern=r"^openpgp-v6/agnusmail-recovery-1$")
    material: Base64Material
    proof: Base64Material
    wallet_certificate: WalletCertificateIn


class RecoveryKeyOut(BaseModel):
    format: str = service.RECOVERY_FORMAT
    material: str
    fingerprint: str
    encryption_fingerprint: str
    expires_at: UtcDatetime
    wallet_account: str
    wallet_certificate: dict[str, object]
    created_at: UtcDatetime

    @classmethod
    def from_key(cls, key: RecoveryKey) -> "RecoveryKeyOut":
        issued = key.wallet_issued_at
        issued = issued.replace(tzinfo=UTC) if issued.tzinfo is None else issued
        return cls(
            material=encode_material(key.material),
            fingerprint=key.fingerprint,
            encryption_fingerprint=key.encryption_fingerprint,
            expires_at=key.expires_at,
            wallet_account=key.wallet_account,
            wallet_certificate={
                "issued_at": int(issued.timestamp()),
                "signature": key.wallet_signature,
            },
            created_at=key.created_at,
        )


class BackupIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    blob: Base64Material


class BackupOut(BaseModel):
    version: int
    blob: str
    created_at: UtcDatetime

    @classmethod
    def from_backup(cls, backup: RecoveryBackup) -> "BackupOut":
        return cls(
            version=backup.version, blob=encode_material(backup.blob), created_at=backup.created_at
        )


@router.post("/key", status_code=201)
async def register_key(
    request: Request, payload: RecoveryKeyIn, session: CurrentSession, db: DbSessionFactory
) -> RecoveryKeyOut:
    settings: Settings = request.app.state.settings
    actor = actor_context(request, session)
    ctx = service.RecoveryContext(
        service=settings.siwe_domain,
        chain_id=settings.siwe_chain_id,
        max_bytes=settings.max_public_key_bytes,
    )
    wallet = service.WalletInput(
        issued_at=payload.wallet_certificate.issued_at,
        signature=payload.wallet_certificate.signature,
    )
    now = datetime.now(UTC)
    return await run_in_transaction(
        db,
        lambda s: RecoveryKeyOut.from_key(
            service.register_recovery_key(
                s, actor, payload.material, payload.proof, wallet, ctx, now
            )
        ),
    )


@router.get("/key")
async def get_key(session: CurrentSession, db: DbSessionFactory) -> RecoveryKeyOut:
    owner = uuid.UUID(session.user_id)

    def work(s: Session) -> RecoveryKeyOut:
        key = service.active_recovery_key(s, owner)
        if key is None:
            raise ResourceNotFoundError("no recovery key")
        return RecoveryKeyOut.from_key(key)

    return await run_in_transaction(db, work)


@router.put("/backup", status_code=201)
async def store_backup(
    request: Request, payload: BackupIn, session: CurrentSession, db: DbSessionFactory
) -> BackupOut:
    actor = actor_context(request, session)
    return await run_in_transaction(
        db, lambda s: BackupOut.from_backup(service.store_backup(s, actor, payload.blob))
    )


@router.get("/backup")
async def get_backup(session: CurrentSession, db: DbSessionFactory) -> BackupOut:
    owner = uuid.UUID(session.user_id)
    return await run_in_transaction(
        db, lambda s: BackupOut.from_backup(service.latest_backup(s, owner))
    )


class BackupFetchIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    # The account's wallet address or e-mail address.
    account: str = Field(min_length=3, max_length=320)


class BackupFetchOut(BaseModel):
    blob: str  # base64 of the OpenPGP message (SKESK v6/Argon2 + SEIPDv2)


LOCAL_DECOY_SECRET = b"agnusmail-local-development-decoy-secret"


@router.post("/backup/fetch", dependencies=[Depends(auth_rate_limit)])
async def fetch_backup(
    request: Request, payload: BackupFetchIn, db: DbSessionFactory
) -> BackupFetchOut:
    """The encrypted backup without a session, for whoever lost the wallet (§8.4).
    Only the 24 words open it. Unknown accounts get a stable decoy of the same shape, so
    the answer never says whether an account exists. Rate limited per IP."""
    settings: Settings = request.app.state.settings
    secret = (
        settings.recovery_decoy_secret.get_secret_value().encode()
        if settings.recovery_decoy_secret
        else LOCAL_DECOY_SECRET  # local environment only (required elsewhere)
    )
    blob = await run_in_transaction(
        db, lambda s: fetch.fetch(s, payload.account, settings.mail_domain, secret)
    )
    return BackupFetchOut(blob=encode_material(blob))


# --- Account migration (spec §8.5) ------------------------------------------------------


class MigrationIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    old_account: str = Field(pattern=r"^0x[0-9a-fA-F]{40}$")
    new_account: str = Field(pattern=r"^0x[0-9a-fA-F]{40}$")
    issued_at: UnixSeconds
    recovery_signature: Base64Material  # v6 binary detached, recovery signing subkey
    acceptance_signature: str = Field(pattern=WALLET_SIGNATURE_PATTERN)  # new wallet


class MigrationOut(BaseModel):
    id: uuid.UUID
    old_account: str
    new_account: str
    status: str
    requested_at: UtcDatetime
    effective_at: UtcDatetime
    finished_at: UtcDatetime | None

    @classmethod
    def from_row(cls, row: AccountMigration) -> "MigrationOut":
        return cls(
            id=row.id,
            old_account=row.old_account,
            new_account=row.new_account,
            status=row.status,
            requested_at=row.requested_at,
            effective_at=row.effective_at,
            finished_at=row.finished_at,
        )


class MigrationList(BaseModel):
    items: list[MigrationOut]


@router.post("/migrations", status_code=202, dependencies=[Depends(auth_rate_limit)])
async def request_migration(
    request: Request, payload: MigrationIn, db: DbSessionFactory
) -> MigrationOut:
    """Start moving an account to a new wallet (no session: the old wallet is lost).
    Effective after 7 days unless a session of the account cancels it."""
    settings: Settings = request.app.state.settings
    ctx = service.RecoveryContext(
        service=settings.siwe_domain,
        chain_id=settings.siwe_chain_id,
        max_bytes=settings.max_public_key_bytes,
    )
    body = migration.MigrationRequest(
        old_account=payload.old_account,
        new_account=payload.new_account,
        issued_at=payload.issued_at,
        recovery_signature=payload.recovery_signature,
        acceptance_signature=payload.acceptance_signature,
    )
    now = datetime.now(UTC)
    return await run_in_transaction(
        db, lambda s: MigrationOut.from_row(migration.request_migration(s, body, ctx, now))
    )


@router.get("/migrations")
async def list_migrations(session: CurrentSession, db: DbSessionFactory) -> MigrationList:
    """Every device of the account should poll this and warn about pending migrations."""
    owner = uuid.UUID(session.user_id)
    return await run_in_transaction(
        db,
        lambda s: MigrationList(
            items=[MigrationOut.from_row(m) for m in migration.list_migrations(s, owner)]
        ),
    )


@router.post("/migrations/{migration_id}/cancel")
async def cancel_migration(
    request: Request, migration_id: uuid.UUID, session: CurrentSession, db: DbSessionFactory
) -> MigrationOut:
    actor = actor_context(request, session)
    now = datetime.now(UTC)
    return await run_in_transaction(
        db,
        lambda s: MigrationOut.from_row(migration.cancel_migration(s, actor, migration_id, now)),
    )


def migration_evidence(row: AccountMigration) -> dict[str, object]:
    """Public proof chain of a completed migration (for the key directory)."""
    issued = row.issued_at.replace(tzinfo=UTC) if row.issued_at.tzinfo is None else row.issued_at
    finished = row.finished_at
    assert finished is not None
    finished = finished.replace(tzinfo=UTC) if finished.tzinfo is None else finished
    return {
        "old_account": row.old_account,
        "new_account": row.new_account,
        "issued_at": int(issued.timestamp()),
        "recovery_signature": encode_material(row.recovery_signature),
        "acceptance_signature": row.acceptance_signature,
        "completed_at": finished.isoformat(),
    }
