"""What a run's job read from the secret store: each reference's location and KV version.

Revision ID: 0034
Revises: 0033
Create Date: 2026-10-15 15:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0034"
down_revision: str | None = "0033"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("runs", sa.Column("secret_reads", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("runs", "secret_reads")
