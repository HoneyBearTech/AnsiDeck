"""Host key scans: ssh-keyscan of an inventory's hosts, run by a worker, kept for an hour.

Revision ID: 0021
Revises: 0020
Create Date: 2026-10-14 18:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0021"
down_revision: str | None = "0020"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "host_key_scans",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("inventory_id", sa.Integer(), nullable=False),
        sa.Column("requested_by_user_id", sa.Integer(), nullable=True),
        sa.Column("requested_by", sa.String(length=150), nullable=False),
        sa.Column("targets", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column(
            "queued_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False),
        sa.Column("worker_id", sa.String(length=255), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("claim_token_hash", sa.String(length=64), nullable=True),
        sa.Column("job_token_hash", sa.String(length=64), nullable=True),
        sa.Column("job_token_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("results", sa.JSON(), nullable=True),
        sa.Column("error", sa.String(length=1000), nullable=True),
        sa.ForeignKeyConstraint(
            ["inventory_id"],
            ["inventories.id"],
            name=op.f("fk_host_key_scans_inventory_id_inventories"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["requested_by_user_id"],
            ["users.id"],
            name=op.f("fk_host_key_scans_requested_by_user_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_host_key_scans")),
    )
    op.create_index(op.f("ix_host_key_scans_inventory_id"), "host_key_scans", ["inventory_id"])
    op.create_index(
        "ix_host_key_scans_queue",
        "host_key_scans",
        ["queued_at", "id"],
        postgresql_where=sa.text("status = 'queued'"),
    )
    op.create_index(
        "ix_host_key_scans_lease",
        "host_key_scans",
        ["lease_expires_at"],
        postgresql_where=sa.text("status = 'running'"),
    )
    op.create_index("ix_host_key_scans_finished_at", "host_key_scans", ["finished_at"])


def downgrade() -> None:
    op.drop_table("host_key_scans")
