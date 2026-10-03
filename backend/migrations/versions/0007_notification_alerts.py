"""Raised ops alerts (worker offline, queue stuck), so each fires once per episode and
sends one all-clear (Phase 4D-2).

Revision ID: 0007
Revises: 0006
Create Date: 2026-10-03 20:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "notification_alerts",
        sa.Column("key", sa.String(length=200), nullable=False),
        sa.Column(
            "raised_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("data", sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint("key", name=op.f("pk_notification_alerts")),
    )


def downgrade() -> None:
    op.drop_table("notification_alerts")
