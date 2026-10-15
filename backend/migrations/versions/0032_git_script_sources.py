"""Inventory scripts from a git source as a kind of dynamic inventory source.

Revision ID: 0032
Revises: 0031
Create Date: 2026-10-15 21:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0032"
down_revision: str | None = "0031"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_PLUGIN = "(kind = 'plugin' AND config IS NOT NULL AND git_source_id IS NULL AND path IS NULL)"
_KIND_FIELDS = (
    f"{_PLUGIN} OR (kind IN ('git_file', 'git_script') AND config IS NULL"
    " AND git_source_id IS NOT NULL AND path IS NOT NULL)"
)
_OLD_KIND_FIELDS = (
    f"{_PLUGIN} OR (kind = 'git_file' AND config IS NULL AND git_source_id IS NOT NULL"
    " AND path IS NOT NULL)"
)


def upgrade() -> None:
    op.drop_constraint(op.f("ck_inventory_sources_kind_fields"), "inventory_sources", type_="check")
    op.create_check_constraint(
        op.f("ck_inventory_sources_kind_fields"), "inventory_sources", _KIND_FIELDS
    )


def downgrade() -> None:
    connection = op.get_bind()
    if connection.execute(
        sa.text("SELECT 1 FROM inventory_sources WHERE kind = 'git_script' LIMIT 1")
    ).first():
        raise RuntimeError("Inventory script sources exist: delete them before downgrading")
    op.drop_constraint(op.f("ck_inventory_sources_kind_fields"), "inventory_sources", type_="check")
    op.create_check_constraint(
        op.f("ck_inventory_sources_kind_fields"), "inventory_sources", _OLD_KIND_FIELDS
    )
