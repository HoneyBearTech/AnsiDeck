"""A revoked API key's name can be used again: unique among the project's keys that aren't
revoked, instead of among all of them (for key rotation).

Revision ID: 0019
Revises: 0018
Create Date: 2026-10-13 19:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0019"
down_revision: str | None = "0018"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_constraint(op.f("uq_api_keys_project_id_name"), "api_keys", type_="unique")
    op.create_index(
        "ux_api_keys_project_name",
        "api_keys",
        ["project_id", "name"],
        unique=True,
        postgresql_where=sa.text("revoked_at IS NULL"),
    )


def downgrade() -> None:
    # Fails if a revoked key shares its name with another key; delete or rename one first.
    op.drop_index("ux_api_keys_project_name", table_name="api_keys")
    op.create_unique_constraint(
        op.f("uq_api_keys_project_id_name"), "api_keys", ["project_id", "name"]
    )
