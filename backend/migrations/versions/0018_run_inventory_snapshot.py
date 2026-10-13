"""Keeps with each run when its inventory snapshot was refreshed and how many hosts it had:
snapshots are pruned once no queued or running run pins them.

Runs whose snapshot is still there get its values; older ones stay NULL.

Revision ID: 0018
Revises: 0017
Create Date: 2026-10-13 18:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0018"
down_revision: str | None = "0017"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("runs", sa.Column("inventory_snapshot_at", sa.DateTime(timezone=True)))
    op.add_column("runs", sa.Column("inventory_snapshot_hosts", sa.Integer()))
    op.execute(
        """
        UPDATE runs
        SET inventory_snapshot_at = s.created_at, inventory_snapshot_hosts = s.host_count
        FROM inventory_snapshots s WHERE runs.inventory_snapshot_id = s.id
        """
    )


def downgrade() -> None:
    op.drop_column("runs", "inventory_snapshot_hosts")
    op.drop_column("runs", "inventory_snapshot_at")
