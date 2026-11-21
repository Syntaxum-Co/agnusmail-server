"""audit hash chain, chain heads and controlled retention purge

Revision ID: 20261111_0003
Revises: 20261111_0002
Create Date: 2026-11-11

- audit_events gains chain_seq / prev_hash / event_hash (per-user SHA-256 chain).
  Existing events are chained in id order with a FROZEN copy of the version-1 encoding
  (migrations must not import application code that may change later).
- audit_chain_heads: tip of each chain (locked by every append) and purge checkpoint.
- Triggers: UPDATE and TRUNCATE stay forbidden. DELETE is allowed only for the retention
  purge: purge mode set in the transaction, event older than 365 days by the database
  clock, and the user's checkpoint already advanced past the event. Heads may only move
  forward and are never deleted.

Offline mode (--sql) cannot backfill: it assumes an empty audit_events table.
"""

import hashlib
import json
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

import sqlalchemy as sa
from alembic import context, op

revision: str = "20261111_0003"
down_revision: str | None = "20261111_0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

OLD_EVENT_TYPES = (
    "'device.registered', 'device.authorized', 'device.revoked', "
    "'key.registered', 'key.superseded', 'key.revoked'"
)
NEW_EVENT_TYPES = OLD_EVENT_TYPES + ", 'audit.purged'"

GENESIS = bytes(32)
DOMAIN_V1 = b"agnusmail/audit-event/v1\n"


def hash_v1(
    *,
    user_id: Any,
    chain_seq: int,
    prev_hash: bytes,
    event_type: str,
    actor_user_id: Any,
    device_id: Any,
    public_key_id: Any,
    details: dict[str, Any],
    created_at: datetime,
) -> bytes:
    """Frozen copy of agnusmail.modules.audit.chain.compute_event_hash (version 1)."""
    utc = created_at.replace(tzinfo=UTC) if created_at.tzinfo is None else created_at
    payload = {
        "v": 1,
        "user_id": str(user_id),
        "seq": chain_seq,
        "prev_hash": prev_hash.hex(),
        "event_type": event_type,
        "actor_user_id": None if actor_user_id is None else str(actor_user_id),
        "device_id": None if device_id is None else str(device_id),
        "public_key_id": None if public_key_id is None else str(public_key_id),
        "details": details,
        "created_at": utc.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
    }
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")
    return hashlib.sha256(DOMAIN_V1 + encoded).digest()


def _backfill() -> None:
    bind = op.get_bind()
    select = sa.text(
        "SELECT id, user_id, event_type, actor_user_id, device_id, public_key_id, "
        "details, created_at FROM audit_events ORDER BY user_id, id"
    )
    rows = bind.execute(select).mappings().all()
    heads: dict[Any, tuple[int, bytes]] = {}
    update = sa.text(
        "UPDATE audit_events SET chain_seq = :seq, prev_hash = :prev, event_hash = :hash "
        "WHERE id = :id"
    )
    for row in rows:
        seq, prev = heads.get(row["user_id"], (0, GENESIS))
        digest = hash_v1(
            user_id=row["user_id"],
            chain_seq=seq + 1,
            prev_hash=prev,
            event_type=row["event_type"],
            actor_user_id=row["actor_user_id"],
            device_id=row["device_id"],
            public_key_id=row["public_key_id"],
            details=row["details"],
            created_at=row["created_at"],
        )
        bind.execute(update, {"seq": seq + 1, "prev": prev, "hash": digest, "id": row["id"]})
        heads[row["user_id"]] = (seq + 1, digest)
    insert = sa.text(
        "INSERT INTO audit_chain_heads (user_id, head_seq, head_hash, purged_through_seq, "
        "purged_through_hash) VALUES (:user_id, :seq, :hash, 0, :genesis)"
    )
    for user_id, (seq, digest) in heads.items():
        bind.execute(insert, {"user_id": user_id, "seq": seq, "hash": digest, "genesis": GENESIS})


def upgrade() -> None:
    op.add_column("audit_events", sa.Column("chain_seq", sa.BigInteger(), nullable=True))
    op.add_column("audit_events", sa.Column("prev_hash", sa.LargeBinary(), nullable=True))
    op.add_column("audit_events", sa.Column("event_hash", sa.LargeBinary(), nullable=True))

    op.create_table(
        "audit_chain_heads",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("head_seq", sa.BigInteger(), nullable=False),
        sa.Column("head_hash", sa.LargeBinary(), nullable=False),
        sa.Column("purged_through_seq", sa.BigInteger(), nullable=False),
        sa.Column("purged_through_hash", sa.LargeBinary(), nullable=False),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "purged_through_seq >= 0",
            name=op.f("ck_audit_chain_heads_purged_through_seq_non_negative"),
        ),
        sa.CheckConstraint(
            "head_seq >= purged_through_seq",
            name=op.f("ck_audit_chain_heads_head_after_checkpoint"),
        ),
        sa.CheckConstraint(
            "length(head_hash) = 32", name=op.f("ck_audit_chain_heads_head_hash_length")
        ),
        sa.CheckConstraint(
            "length(purged_through_hash) = 32",
            name=op.f("ck_audit_chain_heads_purged_through_hash_length"),
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_audit_chain_heads_user_id_users"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("user_id", name=op.f("pk_audit_chain_heads")),
    )

    if not context.is_offline_mode():
        # Chaining existing rows is an UPDATE, which the append-only trigger forbids.
        op.execute("ALTER TABLE audit_events DISABLE TRIGGER audit_events_no_update_delete")
        _backfill()
        op.execute("ALTER TABLE audit_events ENABLE TRIGGER audit_events_no_update_delete")

    op.alter_column("audit_events", "chain_seq", nullable=False)
    op.alter_column("audit_events", "prev_hash", nullable=False)
    op.alter_column("audit_events", "event_hash", nullable=False)
    op.create_check_constraint(
        op.f("ck_audit_events_chain_seq_positive"), "audit_events", "chain_seq >= 1"
    )
    op.create_check_constraint(
        op.f("ck_audit_events_prev_hash_length"), "audit_events", "length(prev_hash) = 32"
    )
    op.create_check_constraint(
        op.f("ck_audit_events_event_hash_length"), "audit_events", "length(event_hash) = 32"
    )
    op.create_unique_constraint(
        op.f("uq_audit_events_user_id_chain_seq"), "audit_events", ["user_id", "chain_seq"]
    )
    op.drop_constraint(op.f("ck_audit_events_event_type_valid"), "audit_events", type_="check")
    op.create_check_constraint(
        op.f("ck_audit_events_event_type_valid"),
        "audit_events",
        f"event_type IN ({NEW_EVENT_TYPES})",
    )

    # UPDATE stays forbidden; DELETE moves to a guarded trigger.
    op.execute("DROP TRIGGER audit_events_no_update_delete ON audit_events")
    op.execute(
        "CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events "
        "FOR EACH ROW EXECUTE FUNCTION audit_events_append_only()"
    )
    op.execute(
        """
        CREATE FUNCTION audit_events_purge_guard() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            -- No '%' placeholders: the statement passes through the driver's paramstyle.
            IF coalesce(current_setting('agnusmail.audit_purge', true), '') <> 'on' THEN
                RAISE EXCEPTION USING
                    MESSAGE = 'audit_events is append-only; DELETE only by the retention purge',
                    ERRCODE = 'insufficient_privilege';
            END IF;
            IF OLD.created_at >= now() - interval '365 days' THEN
                RAISE EXCEPTION USING
                    MESSAGE = 'audit event is inside the 365-day retention floor',
                    ERRCODE = 'insufficient_privilege';
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM audit_chain_heads h
                WHERE h.user_id = OLD.user_id AND OLD.chain_seq <= h.purged_through_seq
            ) THEN
                RAISE EXCEPTION USING
                    MESSAGE = 'audit event is beyond the purge checkpoint',
                    ERRCODE = 'insufficient_privilege';
            END IF;
            RETURN OLD;
        END;
        $$
        """
    )
    op.execute(
        "CREATE TRIGGER audit_events_controlled_delete BEFORE DELETE ON audit_events "
        "FOR EACH ROW EXECUTE FUNCTION audit_events_purge_guard()"
    )

    op.execute(
        """
        CREATE FUNCTION audit_chain_heads_guard() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            IF TG_OP <> 'UPDATE' THEN
                RAISE EXCEPTION USING
                    MESSAGE = 'audit_chain_heads rows are never removed; rejected ' || TG_OP,
                    ERRCODE = 'insufficient_privilege';
            END IF;
            IF NEW.user_id <> OLD.user_id
               OR NEW.head_seq < OLD.head_seq
               OR NEW.purged_through_seq < OLD.purged_through_seq THEN
                RAISE EXCEPTION USING
                    MESSAGE = 'audit chain heads only move forward',
                    ERRCODE = 'insufficient_privilege';
            END IF;
            IF NEW.purged_through_seq <> OLD.purged_through_seq
               AND coalesce(current_setting('agnusmail.audit_purge', true), '') <> 'on' THEN
                RAISE EXCEPTION USING
                    MESSAGE = 'the purge checkpoint moves only in purge mode',
                    ERRCODE = 'insufficient_privilege';
            END IF;
            RETURN NEW;
        END;
        $$
        """
    )
    op.execute(
        "CREATE TRIGGER audit_chain_heads_forward_only BEFORE UPDATE OR DELETE "
        "ON audit_chain_heads FOR EACH ROW EXECUTE FUNCTION audit_chain_heads_guard()"
    )
    op.execute(
        "CREATE TRIGGER audit_chain_heads_no_truncate BEFORE TRUNCATE ON audit_chain_heads "
        "FOR EACH STATEMENT EXECUTE FUNCTION audit_chain_heads_guard()"
    )


def downgrade() -> None:
    if not context.is_offline_mode():
        purged = op.get_bind().execute(
            sa.text("SELECT count(*) FROM audit_events WHERE event_type = 'audit.purged'")
        )
        if purged.scalar_one():
            raise RuntimeError(
                "irreversible: the retention purge already ran (audit.purged events exist)"
            )
    op.execute("DROP TRIGGER IF EXISTS audit_chain_heads_no_truncate ON audit_chain_heads")
    op.execute("DROP TRIGGER IF EXISTS audit_chain_heads_forward_only ON audit_chain_heads")
    op.execute("DROP FUNCTION IF EXISTS audit_chain_heads_guard()")
    op.execute("DROP TRIGGER IF EXISTS audit_events_controlled_delete ON audit_events")
    op.execute("DROP FUNCTION IF EXISTS audit_events_purge_guard()")
    op.execute("DROP TRIGGER IF EXISTS audit_events_no_update ON audit_events")
    op.execute(
        "CREATE TRIGGER audit_events_no_update_delete BEFORE UPDATE OR DELETE ON audit_events "
        "FOR EACH ROW EXECUTE FUNCTION audit_events_append_only()"
    )
    op.drop_constraint(op.f("ck_audit_events_event_type_valid"), "audit_events", type_="check")
    op.create_check_constraint(
        op.f("ck_audit_events_event_type_valid"),
        "audit_events",
        f"event_type IN ({OLD_EVENT_TYPES})",
    )
    op.drop_constraint(op.f("uq_audit_events_user_id_chain_seq"), "audit_events", type_="unique")
    op.drop_constraint(op.f("ck_audit_events_event_hash_length"), "audit_events", type_="check")
    op.drop_constraint(op.f("ck_audit_events_prev_hash_length"), "audit_events", type_="check")
    op.drop_constraint(op.f("ck_audit_events_chain_seq_positive"), "audit_events", type_="check")
    op.drop_table("audit_chain_heads")
    op.drop_column("audit_events", "event_hash")
    op.drop_column("audit_events", "prev_hash")
    op.drop_column("audit_events", "chain_seq")
