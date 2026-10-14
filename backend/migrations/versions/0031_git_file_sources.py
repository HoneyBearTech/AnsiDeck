"""Inventory files from a git source as a kind of dynamic inventory source: the kind, the git
source and path (instead of a plugin config), when the path went missing, and the commit each
refresh and output used.

Revision ID: 0031
Revises: 0030
Create Date: 2026-10-15 18:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0031"
down_revision: str | None = "0030"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_KIND_FIELDS = (
    "(kind = 'plugin' AND config IS NOT NULL AND git_source_id IS NULL AND path IS NULL)"
    " OR (kind = 'git_file' AND config IS NULL AND git_source_id IS NOT NULL"
    " AND path IS NOT NULL)"
)


def upgrade() -> None:
    op.add_column(
        "inventory_sources",
        sa.Column("kind", sa.String(length=20), server_default="plugin", nullable=False),
    )
    op.alter_column("inventory_sources", "config", existing_type=sa.Text(), nullable=True)
    op.add_column("inventory_sources", sa.Column("git_source_id", sa.Integer(), nullable=True))
    op.add_column("inventory_sources", sa.Column("path", sa.String(length=1024), nullable=True))
    op.add_column(
        "inventory_sources", sa.Column("missing_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.create_index(
        op.f("ix_inventory_sources_git_source_id"), "inventory_sources", ["git_source_id"]
    )
    op.create_foreign_key(
        op.f("fk_inventory_sources_git_source_id_git_sources"),
        "inventory_sources",
        "git_sources",
        ["git_source_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_check_constraint(
        op.f("ck_inventory_sources_kind_fields"), "inventory_sources", _KIND_FIELDS
    )
    op.add_column(
        "inventory_refresh_sources", sa.Column("git_snapshot_id", sa.Integer(), nullable=True)
    )
    op.add_column(
        "inventory_refresh_sources", sa.Column("git_commit", sa.String(length=64), nullable=True)
    )
    op.create_foreign_key(
        op.f("fk_inventory_refresh_sources_git_snapshot_id_git_snapshots"),
        "inventory_refresh_sources",
        "git_snapshots",
        ["git_snapshot_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.add_column(
        "inventory_source_outputs", sa.Column("git_commit", sa.String(length=64), nullable=True)
    )


def downgrade() -> None:
    connection = op.get_bind()
    if connection.execute(
        sa.text("SELECT 1 FROM inventory_sources WHERE kind <> 'plugin' LIMIT 1")
    ).first():
        raise RuntimeError("Inventory sources from git exist: delete them before downgrading")
    op.drop_column("inventory_source_outputs", "git_commit")
    op.drop_constraint(
        op.f("fk_inventory_refresh_sources_git_snapshot_id_git_snapshots"),
        "inventory_refresh_sources",
        type_="foreignkey",
    )
    op.drop_column("inventory_refresh_sources", "git_commit")
    op.drop_column("inventory_refresh_sources", "git_snapshot_id")
    op.drop_constraint(op.f("ck_inventory_sources_kind_fields"), "inventory_sources", type_="check")
    op.drop_constraint(
        op.f("fk_inventory_sources_git_source_id_git_sources"),
        "inventory_sources",
        type_="foreignkey",
    )
    op.drop_index(op.f("ix_inventory_sources_git_source_id"), table_name="inventory_sources")
    op.drop_column("inventory_sources", "missing_at")
    op.drop_column("inventory_sources", "path")
    op.drop_column("inventory_sources", "git_source_id")
    op.alter_column("inventory_sources", "config", existing_type=sa.Text(), nullable=False)
    op.drop_column("inventory_sources", "kind")
