"""Run artifacts: the files a playbook left in its ARTIFACTS_DIR, kept as a tar with the run.

Revision ID: 0025
Revises: 0024
Create Date: 2026-10-15 12:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0025"
down_revision: str | None = "0024"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("runs", sa.Column("artifacts_files", sa.JSON(), nullable=True))
    op.add_column("runs", sa.Column("artifacts_bytes", sa.BigInteger(), nullable=True))
    op.add_column("runs", sa.Column("artifacts_tar_bytes", sa.BigInteger(), nullable=True))
    op.add_column("runs", sa.Column("artifacts_sha256", sa.String(length=64), nullable=True))
    op.add_column("runs", sa.Column("artifacts_error", sa.String(length=300), nullable=True))
    op.add_column(
        "runs", sa.Column("artifacts_deleted_at", sa.DateTime(timezone=True), nullable=True)
    )


def downgrade() -> None:
    for column in (
        "artifacts_deleted_at",
        "artifacts_error",
        "artifacts_sha256",
        "artifacts_tar_bytes",
        "artifacts_bytes",
        "artifacts_files",
    ):
        op.drop_column("runs", column)
