"""Whether each worker runs its playbooks isolated, as per-slot users (Phase 4C).

Workers from before this revision never reported it, so their rows stay NULL.

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-03 12:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("workers", sa.Column("isolated", sa.Boolean(), nullable=True))


def downgrade() -> None:
    op.drop_column("workers", "isolated")
