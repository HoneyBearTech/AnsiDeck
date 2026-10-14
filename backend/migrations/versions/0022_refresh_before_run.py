"""Refresh an inventory's sources before a run: an inventory default, the choice on each run
(and the refresh it waits for) and on each run template (NULL: the inventory's default).

Revision ID: 0022
Revises: 0021
Create Date: 2026-10-14 20:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0022"
down_revision: str | None = "0021"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "inventories",
        sa.Column("refresh_before_run", sa.Boolean(), server_default="false", nullable=False),
    )
    op.add_column(
        "runs", sa.Column("refresh_first", sa.Boolean(), server_default="false", nullable=False)
    )
    op.add_column("runs", sa.Column("waiting_refresh_id", sa.Integer(), nullable=True))
    op.create_foreign_key(
        op.f("fk_runs_waiting_refresh_id_inventory_refreshes"),
        "runs",
        "inventory_refreshes",
        ["waiting_refresh_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.add_column("run_templates", sa.Column("refresh_first", sa.Boolean(), nullable=True))


def downgrade() -> None:
    op.drop_column("run_templates", "refresh_first")
    op.drop_constraint(
        op.f("fk_runs_waiting_refresh_id_inventory_refreshes"), "runs", type_="foreignkey"
    )
    op.drop_column("runs", "waiting_refresh_id")
    op.drop_column("runs", "refresh_first")
    op.drop_column("inventories", "refresh_before_run")
