"""devices, public key directory and audit trail

Revision ID: 20261111_0002
Revises: 20261110_0001
Create Date: 2026-11-11

- devices: lifecycle pending -> active -> revoked.
- public_keys: OPAQUE public key material (no parsing; the protocol defines format and
  fingerprint), per-device versions, one active key per (device, format), owner consistency with the
  device enforced by a composite foreign key.
- audit_events: append-only (trigger rejects UPDATE/DELETE/TRUNCATE).
No private keys, secrets or message content are stored.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20261111_0002"
down_revision: str | None = "20261110_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

EVENT_TYPES = (
    "'device.registered', 'device.authorized', 'device.revoked', "
    "'key.registered', 'key.superseded', 'key.revoked'"
)


def upgrade() -> None:
    op.create_table(
        "devices",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=16), server_default="pending", nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("authorized_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_reason", sa.String(length=200), nullable=True),
        sa.CheckConstraint(
            "status IN ('pending', 'active', 'revoked')", name=op.f("ck_devices_status_valid")
        ),
        sa.CheckConstraint(
            "status <> 'active' OR authorized_at IS NOT NULL",
            name=op.f("ck_devices_active_authorized"),
        ),
        sa.CheckConstraint(
            "(status = 'revoked') = (revoked_at IS NOT NULL)",
            name=op.f("ck_devices_revoked_timestamp"),
        ),
        sa.CheckConstraint("length(name) BETWEEN 1 AND 64", name=op.f("ck_devices_name_length")),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name=op.f("fk_devices_user_id_users"), ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_devices")),
        sa.UniqueConstraint("id", "user_id", name=op.f("uq_devices_id_user_id")),
    )
    op.create_index(op.f("ix_devices_user_id_status"), "devices", ["user_id", "status"])

    op.create_table(
        "public_keys",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("device_id", sa.Uuid(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("format", sa.String(length=64), nullable=False),
        sa.Column("material", sa.LargeBinary(), nullable=False),
        sa.Column("material_digest", sa.String(length=71), nullable=False),
        sa.Column("status", sa.String(length=16), server_default="active", nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("superseded_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('active', 'superseded', 'revoked')",
            name=op.f("ck_public_keys_status_valid"),
        ),
        sa.CheckConstraint("version >= 1", name=op.f("ck_public_keys_version_positive")),
        sa.CheckConstraint(
            "length(material) BETWEEN 1 AND 16384", name=op.f("ck_public_keys_material_length")
        ),
        sa.CheckConstraint(
            "length(material_digest) = 71 AND substr(material_digest, 1, 7) = 'sha256:'",
            name=op.f("ck_public_keys_material_digest_format"),
        ),
        sa.CheckConstraint(
            "(status = 'revoked') = (revoked_at IS NOT NULL)",
            name=op.f("ck_public_keys_revoked_timestamp"),
        ),
        sa.CheckConstraint(
            "status <> 'superseded' OR superseded_at IS NOT NULL",
            name=op.f("ck_public_keys_superseded_timestamp"),
        ),
        sa.CheckConstraint(
            "format ~ '^[a-z0-9][a-z0-9._/+-]{0,63}$'", name=op.f("ck_public_keys_format_label")
        ),
        sa.ForeignKeyConstraint(
            ["device_id", "user_id"],
            ["devices.id", "devices.user_id"],
            name=op.f("fk_public_keys_device_id_user_id_devices"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_public_keys_user_id_users"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_public_keys")),
        sa.UniqueConstraint("device_id", "version", name=op.f("uq_public_keys_device_id_version")),
        sa.UniqueConstraint(
            "user_id", "material_digest", name=op.f("uq_public_keys_user_id_material_digest")
        ),
    )
    op.create_index(
        op.f("ix_public_keys_device_id_format"),
        "public_keys",
        ["device_id", "format"],
        unique=True,
        postgresql_where=sa.text("status = 'active'"),
    )
    op.create_index(op.f("ix_public_keys_user_id_status"), "public_keys", ["user_id", "status"])

    op.create_table(
        "audit_events",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("actor_user_id", sa.Uuid(), nullable=True),
        sa.Column("event_type", sa.String(length=48), nullable=False),
        sa.Column("device_id", sa.Uuid(), nullable=True),
        sa.Column("public_key_id", sa.Uuid(), nullable=True),
        sa.Column("details", postgresql.JSONB(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            f"event_type IN ({EVENT_TYPES})", name=op.f("ck_audit_events_event_type_valid")
        ),
        sa.ForeignKeyConstraint(
            ["actor_user_id"],
            ["users.id"],
            name=op.f("fk_audit_events_actor_user_id_users"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["device_id"],
            ["devices.id"],
            name=op.f("fk_audit_events_device_id_devices"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["public_key_id"],
            ["public_keys.id"],
            name=op.f("fk_audit_events_public_key_id_public_keys"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_audit_events_user_id_users"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_events")),
    )
    op.create_index(op.f("ix_audit_events_user_id_id"), "audit_events", ["user_id", "id"])
    op.create_index(op.f("ix_audit_events_device_id_id"), "audit_events", ["device_id", "id"])

    # Append-only audit trail: reject any UPDATE, DELETE or TRUNCATE.
    op.execute(
        """
        CREATE FUNCTION audit_events_append_only() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            -- No '%' placeholders: the statement passes through the driver's paramstyle.
            RAISE EXCEPTION USING
                MESSAGE = 'audit_events is append-only; rejected ' || TG_OP,
                ERRCODE = 'insufficient_privilege';
        END;
        $$
        """
    )
    op.execute(
        "CREATE TRIGGER audit_events_no_update_delete BEFORE UPDATE OR DELETE ON audit_events "
        "FOR EACH ROW EXECUTE FUNCTION audit_events_append_only()"
    )
    op.execute(
        "CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON audit_events "
        "FOR EACH STATEMENT EXECUTE FUNCTION audit_events_append_only()"
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS audit_events_no_truncate ON audit_events")
    op.execute("DROP TRIGGER IF EXISTS audit_events_no_update_delete ON audit_events")
    op.execute("DROP FUNCTION IF EXISTS audit_events_append_only()")
    op.drop_index(op.f("ix_audit_events_device_id_id"), table_name="audit_events")
    op.drop_index(op.f("ix_audit_events_user_id_id"), table_name="audit_events")
    op.drop_table("audit_events")
    op.drop_index(op.f("ix_public_keys_user_id_status"), table_name="public_keys")
    op.drop_index(op.f("ix_public_keys_device_id_format"), table_name="public_keys")
    op.drop_table("public_keys")
    op.drop_index(op.f("ix_devices_user_id_status"), table_name="devices")
    op.drop_table("devices")
