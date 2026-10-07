"""API keys point at the user who created them: a key works only while that user is active and
may still manage the project's keys. Existing keys are matched by username (usernames never
change); a key whose creator is already gone stays unlinked, so it no longer works.

Revision ID: 0016
Revises: 0015
Create Date: 2026-10-07 21:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0016"
down_revision: str | None = "0015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("api_keys", sa.Column("created_by_id", sa.Integer(), nullable=True))
    op.create_foreign_key(
        op.f("fk_api_keys_created_by_id_users"),
        "api_keys",
        "users",
        ["created_by_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index(op.f("ix_api_keys_created_by_id"), "api_keys", ["created_by_id"])
    op.execute(
        "UPDATE api_keys SET created_by_id = users.id FROM users "
        "WHERE users.username = api_keys.created_by"
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_api_keys_created_by_id"), table_name="api_keys")
    op.drop_constraint(op.f("fk_api_keys_created_by_id_users"), "api_keys", type_="foreignkey")
    op.drop_column("api_keys", "created_by_id")
