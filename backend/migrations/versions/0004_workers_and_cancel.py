"""Worker registry (admin Workers page, queued-run hints) and the API key that triggered a
run (a key may cancel only its own runs).

Runs from before this revision have no key id, so no key can cancel them.

Revision ID: 0004
Revises: 0003
Create Date: 2026-09-28 12:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "workers",
        sa.Column("id", sa.String(length=255), nullable=False),
        sa.Column("slots", sa.Integer(), nullable=False),
        sa.Column(
            "first_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_workers")),
    )
    op.add_column("runs", sa.Column("triggered_by_api_key_id", sa.Integer(), nullable=True))
    op.create_foreign_key(
        op.f("fk_runs_triggered_by_api_key_id_api_keys"),
        "runs",
        "api_keys",
        ["triggered_by_api_key_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint(op.f("fk_runs_triggered_by_api_key_id_api_keys"), "runs", type_="foreignkey")
    op.drop_column("runs", "triggered_by_api_key_id")
    op.drop_table("workers")
