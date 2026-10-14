"""Managed SSH host keys per inventory: a mode on each inventory (existing ones "off", new ones
"accept_new"), the trusted keys, and on each run the mode it ran with, what ssh refused and
how many keys it learned. Workers report whether they check host keys.

Revision ID: 0020
Revises: 0019
Create Date: 2026-10-14 12:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0020"
down_revision: str | None = "0019"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Existing inventories keep today's behaviour; turning checking on is the admin's call.
    op.add_column(
        "inventories",
        sa.Column("host_key_checking", sa.String(length=16), server_default="off", nullable=False),
    )
    op.alter_column("inventories", "host_key_checking", server_default="accept_new")
    op.create_table(
        "inventory_host_keys",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("inventory_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=300), nullable=False),
        sa.Column("key_type", sa.String(length=64), nullable=False),
        sa.Column("key_b64", sa.Text(), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("confirmed", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("run_id", sa.Integer(), nullable=True),
        sa.Column("created_by", sa.String(length=150), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("confirmed_by", sa.String(length=150), nullable=True),
        sa.Column("confirmed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["inventory_id"],
            ["inventories.id"],
            name=op.f("fk_inventory_host_keys_inventory_id_inventories"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["runs.id"],
            name=op.f("fk_inventory_host_keys_run_id_runs"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_inventory_host_keys")),
        sa.UniqueConstraint("inventory_id", "name", "key_type", name="uq_inventory_host_key"),
    )
    op.create_index(
        op.f("ix_inventory_host_keys_inventory_id"), "inventory_host_keys", ["inventory_id"]
    )
    op.add_column("runs", sa.Column("host_key_checking", sa.String(length=16), nullable=True))
    op.add_column("runs", sa.Column("host_key_problems", sa.JSON(), nullable=True))
    op.add_column("runs", sa.Column("host_keys_learned", sa.Integer(), nullable=True))
    op.add_column("workers", sa.Column("host_keys", sa.Boolean(), nullable=True))


def downgrade() -> None:
    op.drop_column("workers", "host_keys")
    op.drop_column("runs", "host_keys_learned")
    op.drop_column("runs", "host_key_problems")
    op.drop_column("runs", "host_key_checking")
    op.drop_index(op.f("ix_inventory_host_keys_inventory_id"), table_name="inventory_host_keys")
    op.drop_table("inventory_host_keys")
    op.drop_column("inventories", "host_key_checking")
