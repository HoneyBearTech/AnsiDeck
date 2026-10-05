"""Run templates (Phase 5A): saved playbook + inventory + credential + options, launched again
in one step. References are SET NULL when their item is deleted.

Revision ID: 0013
Revises: 0012
Create Date: 2026-10-05 12:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "run_templates",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("description", sa.String(length=500), nullable=True),
        sa.Column("playbook_id", sa.Integer(), nullable=True),
        sa.Column("inventory_id", sa.Integer(), nullable=True),
        sa.Column("group_name", sa.String(length=255), nullable=True),
        sa.Column("credential_id", sa.Integer(), nullable=True),
        sa.Column("vault_password_id", sa.Integer(), nullable=True),
        sa.Column("uses_vault_password", sa.Boolean(), nullable=False),
        sa.Column("become", sa.Boolean(), nullable=False),
        sa.Column("check_mode", sa.Boolean(), nullable=False),
        sa.Column("diff_mode", sa.Boolean(), nullable=False),
        sa.Column("limit", sa.String(length=500), nullable=True),
        sa.Column("extra_vars", sa.JSON(none_as_null=True), nullable=True),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.String(length=150), nullable=False),
        sa.Column("updated_by", sa.String(length=150), nullable=False),
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
            ["credential_id"],
            ["credentials.id"],
            name=op.f("fk_run_templates_credential_id_credentials"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["inventory_id"],
            ["inventories.id"],
            name=op.f("fk_run_templates_inventory_id_inventories"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["playbook_id"],
            ["playbooks.id"],
            name=op.f("fk_run_templates_playbook_id_playbooks"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name=op.f("fk_run_templates_project_id_projects"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["vault_password_id"],
            ["vault_passwords.id"],
            name=op.f("fk_run_templates_vault_password_id_vault_passwords"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_run_templates")),
        sa.UniqueConstraint("project_id", "name", name="uq_run_template_name"),
    )
    op.create_index(
        op.f("ix_run_templates_project_id"), "run_templates", ["project_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_run_templates_project_id"), table_name="run_templates")
    op.drop_table("run_templates")
