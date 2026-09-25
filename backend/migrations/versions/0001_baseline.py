"""Baseline: the schema as of Phase 4A (the move from SQLite to Postgres).

Existing SQLite installs are brought over with `python -m app.cli import-sqlite`.

Revision ID: 0001
Revises:
Create Date: 2026-09-24 18:26:24.067590
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "audit_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor_user_id", sa.Integer(), nullable=True),
        sa.Column("actor_username", sa.String(length=150), nullable=True),
        sa.Column("project_id", sa.Integer(), nullable=True),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("target_type", sa.String(length=50), nullable=True),
        sa.Column("target_id", sa.Integer(), nullable=True),
        sa.Column("target_name", sa.String(length=255), nullable=True),
        sa.Column("outcome", sa.String(length=20), nullable=False),
        sa.Column("ip", sa.String(length=64), nullable=True),
        sa.Column("detail", sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_events")),
    )
    op.create_index(op.f("ix_audit_events_action"), "audit_events", ["action"], unique=False)
    op.create_index(
        op.f("ix_audit_events_created_at"), "audit_events", ["created_at"], unique=False
    )
    op.create_table(
        "galaxy_installs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("triggered_by", sa.String(length=150), nullable=False),
        sa.Column("requirements_snapshot", sa.Text(), nullable=False),
        sa.Column("upgrade", sa.Boolean(), nullable=False),
        sa.Column("return_code", sa.Integer(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_galaxy_installs")),
    )
    op.create_table(
        "projects",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=150), nullable=False),
        sa.Column("description", sa.String(length=500), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_projects")),
        sa.UniqueConstraint("name", name=op.f("uq_projects_name")),
    )
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(length=150), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=20), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("session_version", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.String(length=150), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("email", sa.String(length=320), nullable=True),
        sa.Column("sso_issuer", sa.String(length=500), nullable=True),
        sa.Column("sso_subject", sa.String(length=255), nullable=True),
        sa.Column("totp_secret", sa.LargeBinary(), nullable=True),
        sa.Column("totp_pending_secret", sa.LargeBinary(), nullable=True),
        sa.Column("totp_last_counter", sa.Integer(), nullable=True),
        sa.Column("totp_recovery_hashes", sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
    )
    op.create_index(op.f("ix_users_username"), "users", ["username"], unique=True)
    op.create_index(
        "ux_users_email_lower", "users", [sa.literal_column("lower(email)")], unique=True
    )
    op.create_index("ux_users_sso_identity", "users", ["sso_issuer", "sso_subject"], unique=True)
    op.create_table(
        "api_keys",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("preset", sa.String(length=20), nullable=False),
        sa.Column("prefix", sa.String(length=16), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("created_by", sa.String(length=150), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_ip", sa.String(length=64), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.String(length=150), nullable=True),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name=op.f("fk_api_keys_project_id_projects"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_api_keys")),
        sa.UniqueConstraint("project_id", "name", name=op.f("uq_api_keys_project_id_name")),
    )
    op.create_index(op.f("ix_api_keys_prefix"), "api_keys", ["prefix"], unique=True)
    op.create_index(op.f("ix_api_keys_project_id"), "api_keys", ["project_id"], unique=False)
    op.create_table(
        "credentials",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=150), nullable=False),
        sa.Column("description", sa.String(length=500), nullable=True),
        sa.Column("encrypted_private_key", sa.LargeBinary(), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["project_id"], ["projects.id"], name=op.f("fk_credentials_project_id_projects")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_credentials")),
        sa.UniqueConstraint("name", name=op.f("uq_credentials_name")),
    )
    op.create_table(
        "inventories",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("description", sa.String(length=500), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["project_id"], ["projects.id"], name=op.f("fk_inventories_project_id_projects")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_inventories")),
        sa.UniqueConstraint("name", name=op.f("uq_inventories_name")),
    )
    op.create_table(
        "playbooks",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=False),
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
            ["project_id"], ["projects.id"], name=op.f("fk_playbooks_project_id_projects")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_playbooks")),
    )
    op.create_table(
        "project_members",
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("role", sa.String(length=20), nullable=False),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name=op.f("fk_project_members_project_id_projects"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_project_members_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("project_id", "user_id", name=op.f("pk_project_members")),
    )
    op.create_table(
        "vault_passwords",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=150), nullable=False),
        sa.Column("description", sa.String(length=500), nullable=True),
        sa.Column("encrypted_password", sa.LargeBinary(), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["project_id"], ["projects.id"], name=op.f("fk_vault_passwords_project_id_projects")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_vault_passwords")),
        sa.UniqueConstraint("name", name=op.f("uq_vault_passwords_name")),
    )
    op.create_table(
        "inventory_groups",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("inventory_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.ForeignKeyConstraint(
            ["inventory_id"],
            ["inventories.id"],
            name=op.f("fk_inventory_groups_inventory_id_inventories"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_inventory_groups")),
        sa.UniqueConstraint("inventory_id", "name", name="uq_group_inventory_name"),
    )
    op.create_table(
        "inventory_hosts",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("inventory_id", sa.Integer(), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=False),
        sa.Column("vars", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(
            ["inventory_id"],
            ["inventories.id"],
            name=op.f("fk_inventory_hosts_inventory_id_inventories"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_inventory_hosts")),
        sa.UniqueConstraint("inventory_id", "hostname", name="uq_host_inventory_hostname"),
    )
    op.create_table(
        "host_group",
        sa.Column("host_id", sa.Integer(), nullable=False),
        sa.Column("group_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["group_id"],
            ["inventory_groups.id"],
            name=op.f("fk_host_group_group_id_inventory_groups"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["host_id"],
            ["inventory_hosts.id"],
            name=op.f("fk_host_group_host_id_inventory_hosts"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("host_id", "group_id", name=op.f("pk_host_group")),
    )
    op.create_table(
        "runs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("playbook_id", sa.Integer(), nullable=True),
        sa.Column("playbook_name", sa.String(length=255), nullable=False),
        sa.Column("inventory_id", sa.Integer(), nullable=True),
        sa.Column("inventory_name", sa.String(length=255), nullable=False),
        sa.Column("group_id", sa.Integer(), nullable=True),
        sa.Column("group_name", sa.String(length=255), nullable=True),
        sa.Column("credential_id", sa.Integer(), nullable=True),
        sa.Column("credential_name", sa.String(length=150), nullable=False),
        sa.Column("vault_password_id", sa.Integer(), nullable=True),
        sa.Column("vault_password_name", sa.String(length=150), nullable=True),
        sa.Column("become", sa.Boolean(), nullable=False),
        sa.Column("check_mode", sa.Boolean(), nullable=False),
        sa.Column("diff_mode", sa.Boolean(), nullable=False),
        sa.Column("limit", sa.String(length=500), nullable=True),
        sa.Column("extra_vars", sa.JSON(), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("triggered_by", sa.String(length=150), nullable=False),
        sa.Column("return_code", sa.Integer(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["credential_id"],
            ["credentials.id"],
            name=op.f("fk_runs_credential_id_credentials"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["group_id"],
            ["inventory_groups.id"],
            name=op.f("fk_runs_group_id_inventory_groups"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["inventory_id"],
            ["inventories.id"],
            name=op.f("fk_runs_inventory_id_inventories"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["playbook_id"],
            ["playbooks.id"],
            name=op.f("fk_runs_playbook_id_playbooks"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["project_id"], ["projects.id"], name=op.f("fk_runs_project_id_projects")
        ),
        sa.ForeignKeyConstraint(
            ["vault_password_id"],
            ["vault_passwords.id"],
            name=op.f("fk_runs_vault_password_id_vault_passwords"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_runs")),
    )


def downgrade() -> None:
    op.drop_table("runs")
    op.drop_table("host_group")
    op.drop_table("inventory_hosts")
    op.drop_table("inventory_groups")
    op.drop_table("vault_passwords")
    op.drop_table("project_members")
    op.drop_table("playbooks")
    op.drop_table("inventories")
    op.drop_table("credentials")
    op.drop_index(op.f("ix_api_keys_project_id"), table_name="api_keys")
    op.drop_index(op.f("ix_api_keys_prefix"), table_name="api_keys")
    op.drop_table("api_keys")
    op.drop_index("ux_users_sso_identity", table_name="users")
    op.drop_index("ux_users_email_lower", table_name="users")
    op.drop_index(op.f("ix_users_username"), table_name="users")
    op.drop_table("users")
    op.drop_table("projects")
    op.drop_table("galaxy_installs")
    op.drop_index(op.f("ix_audit_events_created_at"), table_name="audit_events")
    op.drop_index(op.f("ix_audit_events_action"), table_name="audit_events")
    op.drop_table("audit_events")
