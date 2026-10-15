"""A git source's HTTPS token can be a reference into the secret store (a path under the
project's subtree and a key) instead of being stored encrypted here.

Revision ID: 0033
Revises: 0032
Create Date: 2026-10-15 13:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0033"
down_revision: str | None = "0032"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "git_sources", sa.Column("token_store_path", sa.String(length=400), nullable=True)
    )
    op.add_column("git_sources", sa.Column("token_store_key", sa.String(length=100), nullable=True))
    op.create_check_constraint(
        op.f("ck_git_sources_token_ref"),
        "git_sources",
        "(token_store_path IS NULL) = (token_store_key IS NULL)",
    )
    op.create_check_constraint(
        op.f("ck_git_sources_one_token"),
        "git_sources",
        "encrypted_token IS NULL OR token_store_path IS NULL",
    )
    op.create_check_constraint(
        op.f("ck_git_sources_token_ref_kind"),
        "git_sources",
        "token_store_path IS NULL OR auth_kind = 'https_token'",
    )


def downgrade() -> None:
    connection = op.get_bind()
    if connection.execute(
        sa.text("SELECT 1 FROM git_sources WHERE token_store_path IS NOT NULL LIMIT 1")
    ).first():
        raise RuntimeError(
            "Git sources read their token from the secret store: give them a token (or "
            "delete them) before downgrading"
        )
    op.drop_constraint(op.f("ck_git_sources_token_ref_kind"), "git_sources", type_="check")
    op.drop_constraint(op.f("ck_git_sources_one_token"), "git_sources", type_="check")
    op.drop_constraint(op.f("ck_git_sources_token_ref"), "git_sources", type_="check")
    op.drop_column("git_sources", "token_store_key")
    op.drop_column("git_sources", "token_store_path")
