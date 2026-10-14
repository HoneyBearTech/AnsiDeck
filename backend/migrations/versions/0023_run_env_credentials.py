"""Environment-variable credentials (cloud keys, API tokens) for playbook runs: on each run
(by id, with their names when it was triggered) and on run templates.

Revision ID: 0023
Revises: 0022
Create Date: 2026-10-14 22:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0023"
down_revision: str | None = "0022"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("runs", sa.Column("env_credential_ids", sa.JSON(), nullable=True))
    op.add_column("runs", sa.Column("env_credential_names", sa.JSON(), nullable=True))
    op.add_column("run_templates", sa.Column("env_credential_ids", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("run_templates", "env_credential_ids")
    op.drop_column("runs", "env_credential_names")
    op.drop_column("runs", "env_credential_ids")
