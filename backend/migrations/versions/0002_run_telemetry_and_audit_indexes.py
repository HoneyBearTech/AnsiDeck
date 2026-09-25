"""Run telemetry (lifecycle timestamps, worker, attempt, host counts) and audit indexes.

Existing runs get queued_at = created_at and claimed_at = started_at (before this
revision a run was claimed and started in the same moment); worker and host counts
stay NULL because they were never recorded.

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-24 20:42:01.476016
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_HOST_COUNTS = ("hosts_total", "hosts_ok", "hosts_changed", "hosts_failed", "hosts_unreachable")


def upgrade() -> None:
    # The composite index covers every lookup the single-column one served.
    op.drop_index("ix_audit_events_action", table_name="audit_events")
    op.create_index("ix_audit_events_action_created_at", "audit_events", ["action", "created_at"])

    op.add_column("runs", sa.Column("queued_at", sa.DateTime(timezone=True), nullable=True))
    op.execute("UPDATE runs SET queued_at = created_at")
    op.alter_column("runs", "queued_at", nullable=False, server_default=sa.text("now()"))

    op.add_column("runs", sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True))
    op.execute("UPDATE runs SET claimed_at = started_at")

    op.add_column("runs", sa.Column("worker_id", sa.String(length=255), nullable=True))
    op.add_column("runs", sa.Column("attempt", sa.Integer(), server_default="1", nullable=False))
    for name in _HOST_COUNTS:
        op.add_column("runs", sa.Column(name, sa.Integer(), nullable=True))


def downgrade() -> None:
    for name in reversed(_HOST_COUNTS):
        op.drop_column("runs", name)
    for name in ("attempt", "worker_id", "claimed_at", "queued_at"):
        op.drop_column("runs", name)
    op.drop_index("ix_audit_events_action_created_at", table_name="audit_events")
    op.create_index("ix_audit_events_action", "audit_events", ["action"])
