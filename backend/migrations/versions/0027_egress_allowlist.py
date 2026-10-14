"""Restricting runs' network egress to their inventory's hosts: the inventory setting and its
extra entries, what each run was allowed and refused, and which workers can do it. Existing
inventories stay unrestricted.

Revision ID: 0027
Revises: 0026
Create Date: 2026-10-14 18:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0027"
down_revision: str | None = "0026"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "inventories",
        sa.Column("egress_restricted", sa.Boolean(), server_default="false", nullable=False),
    )
    op.add_column("inventories", sa.Column("egress_extras", sa.JSON(), nullable=True))
    op.add_column("runs", sa.Column("egress_restricted", sa.Boolean(), nullable=True))
    op.add_column("runs", sa.Column("egress_allowlist", sa.JSON(), nullable=True))
    op.add_column("runs", sa.Column("egress_refused", sa.JSON(), nullable=True))
    op.add_column("workers", sa.Column("egress_allowlist", sa.Boolean(), nullable=True))


def downgrade() -> None:
    op.drop_column("workers", "egress_allowlist")
    op.drop_column("runs", "egress_refused")
    op.drop_column("runs", "egress_allowlist")
    op.drop_column("runs", "egress_restricted")
    op.drop_column("inventories", "egress_extras")
    op.drop_column("inventories", "egress_restricted")
