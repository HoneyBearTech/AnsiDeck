"""Playbook checks (Phase 5B): ansible-lint jobs claimed by workers like inventory refreshes.
One queued check per person; rows are pruned an hour after they end.

Revision ID: 0014
Revises: 0013
Create Date: 2026-10-05 13:30:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0014"
down_revision: str | None = "0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "lint_jobs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("requested_by_user_id", sa.Integer(), nullable=False),
        sa.Column("requested_by", sa.String(length=150), nullable=False),
        sa.Column("playbook_id", sa.Integer(), nullable=True),
        sa.Column("target", sa.String(length=1024), nullable=False),
        sa.Column("content", sa.Text(), nullable=True),
        sa.Column("content_sha256", sa.String(length=64), nullable=True),
        sa.Column("git_snapshot_id", sa.Integer(), nullable=True),
        sa.Column("git_commit", sa.String(length=64), nullable=True),
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
        sa.Column("findings", sa.JSON(), nullable=True),
        sa.Column("findings_total", sa.Integer(), nullable=True),
        sa.Column("truncated", sa.Boolean(), nullable=False),
        sa.Column("external", sa.Integer(), nullable=False),
        sa.Column("repo_config", sa.Boolean(), nullable=False),
        sa.Column("error", sa.String(length=1000), nullable=True),
        sa.Column("scrubbed", sa.Boolean(), nullable=False),
        sa.Column("ansible_lint_version", sa.String(length=40), nullable=True),
        sa.ForeignKeyConstraint(
            ["git_snapshot_id"],
            ["git_snapshots.id"],
            name=op.f("fk_lint_jobs_git_snapshot_id_git_snapshots"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["playbook_id"],
            ["playbooks.id"],
            name=op.f("fk_lint_jobs_playbook_id_playbooks"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name=op.f("fk_lint_jobs_project_id_projects"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["requested_by_user_id"],
            ["users.id"],
            name=op.f("fk_lint_jobs_requested_by_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_lint_jobs")),
    )
    op.create_index("ix_lint_jobs_finished_at", "lint_jobs", ["finished_at"], unique=False)
    op.create_index(
        "ix_lint_jobs_lease",
        "lint_jobs",
        ["lease_expires_at"],
        unique=False,
        postgresql_where=sa.text("status = 'running'"),
    )
    op.create_index(
        "ix_lint_jobs_queue",
        "lint_jobs",
        ["queued_at", "id"],
        unique=False,
        postgresql_where=sa.text("status = 'queued'"),
    )
    op.create_index(
        "ux_lint_jobs_queued_user",
        "lint_jobs",
        ["requested_by_user_id"],
        unique=True,
        postgresql_where=sa.text("status = 'queued'"),
    )


def downgrade() -> None:
    op.drop_index(
        "ux_lint_jobs_queued_user",
        table_name="lint_jobs",
        postgresql_where=sa.text("status = 'queued'"),
    )
    op.drop_index(
        "ix_lint_jobs_queue", table_name="lint_jobs", postgresql_where=sa.text("status = 'queued'")
    )
    op.drop_index(
        "ix_lint_jobs_lease", table_name="lint_jobs", postgresql_where=sa.text("status = 'running'")
    )
    op.drop_index("ix_lint_jobs_finished_at", table_name="lint_jobs")
    op.drop_table("lint_jobs")
