"""Whether each worker keeps its runs away from the API and cloud metadata (its egress filter).

Workers from before this revision never reported it, so their rows stay NULL.

Revision ID: 0017
Revises: 0016
Create Date: 2026-10-13 12:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0017"
down_revision: str | None = "0016"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("workers", sa.Column("egress_filtered", sa.Boolean(), nullable=True))


def downgrade() -> None:
    op.drop_column("workers", "egress_filtered")
