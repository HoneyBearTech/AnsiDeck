"""Dynamic inventory sources (Phase 4G-2): plugin configs attached to an inventory, refreshes
claimed by workers like runs, and the snapshots they produce (runs pin one when triggered).

Revision ID: 0012
Revises: 0011
Create Date: 2026-10-05 12:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_REFRESHES_VIEW = """
SELECT r.id AS refresh_id, r.project_id, r.inventory_id, r.status, r.trigger,
       r.queued_at, r.started_at, r.finished_at,
       EXTRACT(EPOCH FROM (r.finished_at - r.started_at)) AS duration_seconds,
       r.worker_id AS worker, s.host_count, s.group_count
FROM inventory_refreshes r LEFT JOIN inventory_snapshots s ON s.id = r.snapshot_id
"""


def upgrade() -> None:
    op.create_table(
        "inventory_snapshots",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("inventory_id", sa.Integer(), nullable=False),
        sa.Column("refresh_id", sa.Integer(), nullable=True),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("host_count", sa.Integer(), nullable=False),
        sa.Column("group_count", sa.Integer(), nullable=False),
        sa.Column("warnings", sa.JSON(), nullable=False),
        sa.Column("sources", sa.JSON(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("superseded_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["inventory_id"],
            ["inventories.id"],
            name=op.f("fk_inventory_snapshots_inventory_id_inventories"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_inventory_snapshots")),
    )
    op.create_index(
        op.f("ix_inventory_snapshots_inventory_id"), "inventory_snapshots", ["inventory_id"]
    )
    op.add_column(
        "inventories",
        sa.Column("refresh_interval_seconds", sa.Integer(), server_default="0", nullable=False),
    )
    op.add_column("inventories", sa.Column("current_snapshot_id", sa.Integer(), nullable=True))
    op.create_foreign_key(
        op.f("fk_inventories_current_snapshot_id_inventory_snapshots"),
        "inventories",
        "inventory_snapshots",
        ["current_snapshot_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_table(
        "inventory_sources",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("inventory_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("plugin", sa.String(length=200), nullable=False),
        sa.Column("config", sa.Text(), nullable=False),
        sa.Column("credential_id", sa.Integer(), nullable=True),
        sa.Column("enabled", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("position", sa.Integer(), server_default="0", nullable=False),
        sa.Column("created_by", sa.String(length=150), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["credential_id"],
            ["credentials.id"],
            name=op.f("fk_inventory_sources_credential_id_credentials"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["inventory_id"],
            ["inventories.id"],
            name=op.f("fk_inventory_sources_inventory_id_inventories"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_inventory_sources")),
        sa.UniqueConstraint("inventory_id", "name", name="uq_inventory_source_name"),
    )
    op.create_index(
        op.f("ix_inventory_sources_credential_id"), "inventory_sources", ["credential_id"]
    )
    op.create_index(
        op.f("ix_inventory_sources_inventory_id"), "inventory_sources", ["inventory_id"]
    )
    op.create_table(
        "inventory_refreshes",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("inventory_id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("trigger", sa.String(length=20), nullable=False),
        sa.Column("requested_by", sa.String(length=150), nullable=True),
        sa.Column(
            "queued_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
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
        sa.Column("sources", sa.JSON(), nullable=True),
        sa.Column("output_bytes", sa.Integer(), nullable=True),
        sa.Column("error", sa.String(length=1000), nullable=True),
        sa.Column("snapshot_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(
            ["inventory_id"],
            ["inventories.id"],
            name=op.f("fk_inventory_refreshes_inventory_id_inventories"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name=op.f("fk_inventory_refreshes_project_id_projects"),
        ),
        sa.ForeignKeyConstraint(
            ["snapshot_id"],
            ["inventory_snapshots.id"],
            name=op.f("fk_inventory_refreshes_snapshot_id_inventory_snapshots"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_inventory_refreshes")),
    )
    op.create_index(
        op.f("ix_inventory_refreshes_inventory_id"), "inventory_refreshes", ["inventory_id"]
    )
    for name, where in (("queued", "status = 'queued'"), ("running", "status = 'running'")):
        op.create_index(
            f"ux_inventory_refreshes_{name}",
            "inventory_refreshes",
            ["inventory_id"],
            unique=True,
            postgresql_where=sa.text(where),
        )
    op.create_index(
        "ix_inventory_refreshes_queue",
        "inventory_refreshes",
        ["queued_at", "id"],
        postgresql_where=sa.text("status = 'queued'"),
    )
    op.create_index(
        "ix_inventory_refreshes_lease",
        "inventory_refreshes",
        ["lease_expires_at"],
        postgresql_where=sa.text("status = 'running'"),
    )
    op.add_column("runs", sa.Column("inventory_snapshot_id", sa.Integer(), nullable=True))
    op.create_foreign_key(
        op.f("fk_runs_inventory_snapshot_id_inventory_snapshots"),
        "runs",
        "inventory_snapshots",
        ["inventory_snapshot_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.execute(
        f"CREATE VIEW analytics.inventory_refreshes WITH (security_barrier) AS {_REFRESHES_VIEW}"
    )


def downgrade() -> None:
    op.execute("DROP VIEW analytics.inventory_refreshes")
    op.drop_constraint(
        op.f("fk_runs_inventory_snapshot_id_inventory_snapshots"), "runs", type_="foreignkey"
    )
    op.drop_column("runs", "inventory_snapshot_id")
    op.drop_table("inventory_refreshes")
    op.drop_table("inventory_sources")
    op.drop_constraint(
        op.f("fk_inventories_current_snapshot_id_inventory_snapshots"),
        "inventories",
        type_="foreignkey",
    )
    op.drop_column("inventories", "current_snapshot_id")
    op.drop_column("inventories", "refresh_interval_seconds")
    op.drop_table("inventory_snapshots")
