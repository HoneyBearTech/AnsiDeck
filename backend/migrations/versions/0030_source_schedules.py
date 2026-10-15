"""Per-source schedules: a source's own refresh interval (or the inventory's), when a refresh
was last queued to run it, and which sources a refresh runs.

Revision ID: 0030
Revises: 0029
Create Date: 2026-10-15 15:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0030"
down_revision: str | None = "0029"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "inventory_sources", sa.Column("refresh_interval_seconds", sa.Integer(), nullable=True)
    )
    # Left empty: each inventory's first refresh after the upgrade runs every source.
    op.add_column(
        "inventory_sources",
        sa.Column("last_queued_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column("inventory_refreshes", sa.Column("scope", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("inventory_refreshes", "scope")
    op.drop_column("inventory_sources", "last_queued_at")
    op.drop_column("inventory_sources", "refresh_interval_seconds")
