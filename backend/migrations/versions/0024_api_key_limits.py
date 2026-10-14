"""Optional limits on API keys: the addresses they may be used from, and the playbooks and
inventories they may start runs of (NULL: any).

Revision ID: 0024
Revises: 0023
Create Date: 2026-10-15 09:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0024"
down_revision: str | None = "0023"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_COLUMNS = ("allowed_networks", "allowed_playbook_ids", "allowed_inventory_ids")


def upgrade() -> None:
    for column in _COLUMNS:
        op.add_column("api_keys", sa.Column(column, sa.JSON(), nullable=True))


def downgrade() -> None:
    for column in reversed(_COLUMNS):
        op.drop_column("api_keys", column)
