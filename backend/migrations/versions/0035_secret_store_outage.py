"""While the secret store is down, runs and refreshes that need it wait: a one-row table
records the outage (its kind, since when, and until when the last sighting holds).

Revision ID: 0035
Revises: 0034
Create Date: 2026-10-15 18:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0035"
down_revision: str | None = "0034"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "secret_store_outage",
        sa.Column("id", sa.Integer(), autoincrement=False, nullable=False),
        sa.Column("kind", sa.String(length=30), nullable=False),
        sa.Column(
            "since", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.Column("hold_until", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("id = 1", name=op.f("ck_secret_store_outage_single_row")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_secret_store_outage")),
    )


def downgrade() -> None:
    op.drop_table("secret_store_outage")
