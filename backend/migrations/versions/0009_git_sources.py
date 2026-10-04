"""Git sources (Phase 4E): repositories a project's playbooks are synced from, the synced
commits (snapshots runs execute in), synced playbooks, and the commit a run used.
analytics.runs gains the source name and commit.

Revision ID: 0009
Revises: 0008
Create Date: 2026-10-04 20:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_RUNS_COLUMNS = """
        SELECT r.id AS run_id, r.project_id, p.name AS project,
               r.playbook_id, r.playbook_name, r.inventory_id, r.inventory_name, r.group_name,
               r.status, r.status_reason, r.return_code,
               r.check_mode, r.diff_mode, r.become,
               r.triggered_by, r.triggered_by_api_key_id IS NOT NULL AS via_api_key,
               r.attempt, r.worker_id AS worker,
               r.cancel_requested_at IS NOT NULL AS cancel_requested,
               r.timeout_seconds,
               r.created_at, r.queued_at, r.claimed_at, r.started_at, r.finished_at,
               extract(epoch FROM r.claimed_at - r.queued_at)::float8 AS queue_wait_seconds,
               extract(epoch FROM r.finished_at - r.started_at)::float8 AS run_seconds,
               extract(epoch FROM r.finished_at - r.queued_at)::float8 AS total_seconds,
               r.hosts_total, r.hosts_ok, r.hosts_changed, r.hosts_failed,
               r.hosts_unreachable{extra}
        FROM public.runs r
        JOIN public.projects p ON p.id = r.project_id
"""
# 0008's view, as it was (the downgrade restores it).
_RUNS_0008 = _RUNS_COLUMNS.format(extra="")
# New columns go at the end: CREATE OR REPLACE VIEW may only append.
_RUNS_0009 = _RUNS_COLUMNS.format(extra=",\n               r.git_source_name, r.git_commit")


def upgrade() -> None:
    op.create_table(
        "git_sources",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("url", sa.String(length=500), nullable=False),
        sa.Column("branch", sa.String(length=255), nullable=False),
        sa.Column("subdir", sa.String(length=500), nullable=True),
        sa.Column("web_url", sa.String(length=500), nullable=True),
        sa.Column("playbook_globs", sa.JSON(), nullable=False),
        sa.Column("auth_kind", sa.String(length=20), nullable=False),
        sa.Column("credential_id", sa.Integer(), nullable=True),
        sa.Column("https_username", sa.String(length=255), nullable=True),
        sa.Column("encrypted_token", sa.LargeBinary(), nullable=True),
        sa.Column("ssh_known_hosts", sa.Text(), nullable=True),
        sa.Column("auto_sync_seconds", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("current_snapshot_id", sa.Integer(), nullable=True),
        sa.Column("sync_requested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_sync_started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_sync_finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_sync_status", sa.String(length=10), nullable=True),
        sa.Column("last_sync_error", sa.String(length=1000), nullable=True),
        sa.Column("created_by", sa.String(length=150), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name=op.f("fk_git_sources_project_id_projects"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["credential_id"],
            ["credentials.id"],
            name=op.f("fk_git_sources_credential_id_credentials"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_git_sources")),
        sa.UniqueConstraint("project_id", "name", name=op.f("uq_git_sources_project_id_name")),
    )
    op.create_index(op.f("ix_git_sources_project_id"), "git_sources", ["project_id"])
    op.create_index(op.f("ix_git_sources_credential_id"), "git_sources", ["credential_id"])

    op.create_table(
        "git_snapshots",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("source_id", sa.Integer(), nullable=False),
        sa.Column("commit", sa.String(length=64), nullable=False),
        sa.Column("commit_subject", sa.String(length=255), nullable=False),
        sa.Column("commit_author", sa.String(length=255), nullable=False),
        sa.Column("committed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("file_count", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("warnings", sa.JSON(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("superseded_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["git_sources.id"],
            name=op.f("fk_git_snapshots_source_id_git_sources"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_git_snapshots")),
        sa.UniqueConstraint("source_id", "commit", name=op.f("uq_git_snapshots_source_id_commit")),
    )
    op.create_index(op.f("ix_git_snapshots_source_id"), "git_snapshots", ["source_id"])
    op.create_foreign_key(
        op.f("fk_git_sources_current_snapshot_id_git_snapshots"),
        "git_sources",
        "git_snapshots",
        ["current_snapshot_id"],
        ["id"],
        ondelete="SET NULL",
    )

    op.add_column("playbooks", sa.Column("source_id", sa.Integer(), nullable=True))
    op.add_column("playbooks", sa.Column("repo_path", sa.String(length=1024), nullable=True))
    op.add_column("playbooks", sa.Column("missing_at", sa.DateTime(timezone=True), nullable=True))
    op.create_foreign_key(
        op.f("fk_playbooks_source_id_git_sources"),
        "playbooks",
        "git_sources",
        ["source_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_index(op.f("ix_playbooks_source_id"), "playbooks", ["source_id"])
    op.create_unique_constraint(
        op.f("uq_playbooks_source_id_repo_path"), "playbooks", ["source_id", "repo_path"]
    )

    op.add_column("runs", sa.Column("git_source_id", sa.Integer(), nullable=True))
    op.add_column("runs", sa.Column("git_source_name", sa.String(length=100), nullable=True))
    op.add_column("runs", sa.Column("git_snapshot_id", sa.Integer(), nullable=True))
    op.add_column("runs", sa.Column("git_commit", sa.String(length=64), nullable=True))
    op.add_column("runs", sa.Column("playbook_path", sa.String(length=1024), nullable=True))
    op.create_foreign_key(
        op.f("fk_runs_git_source_id_git_sources"),
        "runs",
        "git_sources",
        ["git_source_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_foreign_key(
        op.f("fk_runs_git_snapshot_id_git_snapshots"),
        "runs",
        "git_snapshots",
        ["git_snapshot_id"],
        ["id"],
        ondelete="SET NULL",
    )

    op.execute(f"CREATE OR REPLACE VIEW analytics.runs WITH (security_barrier) AS {_RUNS_0009}")


def downgrade() -> None:
    # A view can't lose columns in place. A Grafana role keeps its access through the
    # default privileges analytics-grant set (they cover views created later).
    op.execute("DROP VIEW analytics.runs")
    op.execute(f"CREATE VIEW analytics.runs WITH (security_barrier) AS {_RUNS_0008}")

    op.drop_constraint(op.f("fk_runs_git_snapshot_id_git_snapshots"), "runs", type_="foreignkey")
    op.drop_constraint(op.f("fk_runs_git_source_id_git_sources"), "runs", type_="foreignkey")
    for column in ("playbook_path", "git_commit", "git_snapshot_id", "git_source_name"):
        op.drop_column("runs", column)
    op.drop_column("runs", "git_source_id")

    op.drop_constraint(op.f("uq_playbooks_source_id_repo_path"), "playbooks", type_="unique")
    op.drop_index(op.f("ix_playbooks_source_id"), table_name="playbooks")
    op.drop_constraint(op.f("fk_playbooks_source_id_git_sources"), "playbooks", type_="foreignkey")
    for column in ("missing_at", "repo_path", "source_id"):
        op.drop_column("playbooks", column)

    op.drop_constraint(
        op.f("fk_git_sources_current_snapshot_id_git_snapshots"), "git_sources", type_="foreignkey"
    )
    op.drop_index(op.f("ix_git_snapshots_source_id"), table_name="git_snapshots")
    op.drop_table("git_snapshots")
    op.drop_index(op.f("ix_git_sources_credential_id"), table_name="git_sources")
    op.drop_index(op.f("ix_git_sources_project_id"), table_name="git_sources")
    op.drop_table("git_sources")
