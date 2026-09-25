"""Job queue: playbook snapshot, timeouts, worker leases and tokens, cancel requests,
idempotent log appends; install leases.

Runs and installs still queued or running were started by the old in-process engine, which
is gone: nothing will ever finish them, so they are failed with a reason (this also has to
happen before the one-running-run-per-inventory index can be created).

Revision ID: 0003
Revises: 0002
Create Date: 2026-09-25 14:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

INTERRUPTED = "interrupted: never finished before the job-queue upgrade"


def upgrade() -> None:
    op.add_column("runs", sa.Column("playbook_snapshot", sa.Text(), nullable=True))
    op.add_column("runs", sa.Column("playbook_sha256", sa.String(length=64), nullable=True))
    op.add_column(
        "runs", sa.Column("timeout_seconds", sa.Integer(), server_default="7200", nullable=False)
    )
    op.add_column("runs", sa.Column("status_reason", sa.String(length=500), nullable=True))
    op.add_column("runs", sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("runs", sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("runs", sa.Column("claim_token_hash", sa.String(length=64), nullable=True))
    op.add_column("runs", sa.Column("job_token_hash", sa.String(length=64), nullable=True))
    op.add_column(
        "runs", sa.Column("job_token_expires_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column(
        "runs", sa.Column("cancel_requested_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("runs", sa.Column("cancel_requested_by", sa.String(length=150), nullable=True))
    op.add_column("runs", sa.Column("log_seq", sa.Integer(), server_default="0", nullable=False))
    op.add_column(
        "runs", sa.Column("log_bytes", sa.BigInteger(), server_default="0", nullable=False)
    )
    op.add_column("galaxy_installs", sa.Column("status_reason", sa.String(length=500)))
    op.add_column(
        "galaxy_installs", sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True)
    )

    for table in ("runs", "galaxy_installs"):
        op.execute(
            sa.text(
                f"UPDATE {table} SET status = 'failed', status_reason = :reason, "
                "finished_at = COALESCE(finished_at, now()) "
                "WHERE status IN ('queued', 'running')"
            ).bindparams(reason=INTERRUPTED)
        )

    op.create_index(
        "ux_runs_running_inventory",
        "runs",
        ["inventory_id"],
        unique=True,
        postgresql_where=sa.text("status = 'running'"),
    )
    op.create_index(
        "ix_runs_queue", "runs", ["queued_at", "id"], postgresql_where=sa.text("status = 'queued'")
    )
    op.create_index(
        "ix_runs_lease",
        "runs",
        ["lease_expires_at"],
        postgresql_where=sa.text("status = 'running'"),
    )


def downgrade() -> None:
    # 0002 only knew queued/running/success/failed.
    op.execute("UPDATE runs SET status = 'failed' WHERE status IN ('cancelled', 'timed_out')")
    op.drop_index("ix_runs_lease", table_name="runs")
    op.drop_index("ix_runs_queue", table_name="runs")
    op.drop_index("ux_runs_running_inventory", table_name="runs")
    op.drop_column("galaxy_installs", "lease_expires_at")
    op.drop_column("galaxy_installs", "status_reason")
    for name in (
        "log_bytes",
        "log_seq",
        "cancel_requested_by",
        "cancel_requested_at",
        "job_token_expires_at",
        "job_token_hash",
        "claim_token_hash",
        "heartbeat_at",
        "lease_expires_at",
        "status_reason",
        "timeout_seconds",
        "playbook_sha256",
        "playbook_snapshot",
    ):
        op.drop_column("runs", name)
