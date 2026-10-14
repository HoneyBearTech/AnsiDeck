"""Dynamic inventory refreshes run each source on its own: every source's last good output,
what each source did in each refresh, a refresh's stage, and each source's last error.

Revision ID: 0029
Revises: 0028
Create Date: 2026-10-15 12:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0029"
down_revision: str | None = "0028"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "inventory_sources", sa.Column("last_error", sa.String(length=1000), nullable=True)
    )
    op.add_column(
        "inventory_sources",
        sa.Column("last_finished_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column("inventory_refreshes", sa.Column("stage", sa.String(length=10), nullable=True))
    op.create_table(
        "inventory_source_outputs",
        sa.Column("source_id", sa.Integer(), nullable=False),
        sa.Column("inventory_id", sa.Integer(), nullable=False),
        sa.Column("refresh_id", sa.Integer(), nullable=True),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("host_count", sa.Integer(), nullable=False),
        sa.Column("group_count", sa.Integer(), nullable=False),
        sa.Column("output_bytes", sa.Integer(), nullable=False),
        sa.Column("warnings", sa.JSON(), nullable=False),
        sa.Column("input_sha256", sa.String(length=64), nullable=False),
        sa.Column(
            "refreshed_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["inventory_id"],
            ["inventories.id"],
            name=op.f("fk_inventory_source_outputs_inventory_id_inventories"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["inventory_sources.id"],
            name=op.f("fk_inventory_source_outputs_source_id_inventory_sources"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("source_id", name=op.f("pk_inventory_source_outputs")),
    )
    op.create_index(
        op.f("ix_inventory_source_outputs_inventory_id"),
        "inventory_source_outputs",
        ["inventory_id"],
    )
    op.create_table(
        "inventory_refresh_sources",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("refresh_id", sa.Integer(), nullable=False),
        sa.Column("source_id", sa.Integer(), nullable=True),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("plugin", sa.String(length=200), nullable=False),
        sa.Column("ran", sa.Boolean(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=True),
        sa.Column("error", sa.String(length=1000), nullable=True),
        sa.Column("input_sha256", sa.String(length=64), nullable=True),
        sa.Column("host_count", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(
            ["refresh_id"],
            ["inventory_refreshes.id"],
            name=op.f("fk_inventory_refresh_sources_refresh_id_inventory_refreshes"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["inventory_sources.id"],
            name=op.f("fk_inventory_refresh_sources_source_id_inventory_sources"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_inventory_refresh_sources")),
    )
    op.create_index(
        op.f("ix_inventory_refresh_sources_refresh_id"),
        "inventory_refresh_sources",
        ["refresh_id"],
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_inventory_refresh_sources_refresh_id"), table_name="inventory_refresh_sources"
    )
    op.drop_table("inventory_refresh_sources")
    op.drop_index(
        op.f("ix_inventory_source_outputs_inventory_id"), table_name="inventory_source_outputs"
    )
    op.drop_table("inventory_source_outputs")
    op.drop_column("inventory_refreshes", "stage")
    op.drop_column("inventory_sources", "last_finished_at")
    op.drop_column("inventory_sources", "last_error")
