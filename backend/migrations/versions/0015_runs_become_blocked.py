"""Runs remember whether they were triggered by someone without runs:become: such a run gets
ansible_become: false at execution, kept out of its stored extra vars.

Revision ID: 0015
Revises: 0014
Create Date: 2026-10-06 23:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0015"
down_revision: str | None = "0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "runs",
        sa.Column("become_blocked", sa.Boolean(), server_default="false", nullable=False),
    )


def downgrade() -> None:
    op.drop_column("runs", "become_blocked")
