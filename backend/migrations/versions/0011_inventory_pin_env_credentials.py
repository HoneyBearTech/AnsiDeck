"""Dynamic inventory foundation (Phase 4G-1): runs pin the inventory's static hosts and groups
when they are triggered, and credentials get a kind: "ssh" (a private key, as before) or "env"
(named variables for inventory plugins, encrypted here or a whole secret store secret).

Revision ID: 0011
Revises: 0010
Create Date: 2026-10-05 09:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SECRET_BY_KIND = (
    "CASE kind"  # noqa: S105 - column names, not secrets
    " WHEN 'ssh' THEN encrypted_env IS NULL"
    " AND (encrypted_private_key IS NULL) <> (store_path IS NULL)"
    " AND (store_path IS NULL) = (store_key IS NULL)"
    " WHEN 'env' THEN encrypted_private_key IS NULL AND store_key IS NULL"
    " AND (encrypted_env IS NULL) <> (store_path IS NULL)"
    " ELSE false END"
)


def upgrade() -> None:
    op.add_column("runs", sa.Column("inventory_static", sa.JSON(), nullable=True))
    op.add_column("runs", sa.Column("inventory_sha256", sa.String(length=64), nullable=True))

    op.add_column(
        "credentials",
        sa.Column("kind", sa.String(length=10), server_default="ssh", nullable=False),
    )
    op.add_column("credentials", sa.Column("encrypted_env", sa.LargeBinary(), nullable=True))
    op.add_column("credentials", sa.Column("env_names", sa.JSON(), nullable=True))
    op.drop_constraint(op.f("ck_credentials_store_ref"), "credentials", type_="check")
    op.drop_constraint(op.f("ck_credentials_one_secret"), "credentials", type_="check")
    op.create_check_constraint(op.f("ck_credentials_kind"), "credentials", "kind IN ('ssh', 'env')")
    op.create_check_constraint(
        op.f("ck_credentials_secret_by_kind"), "credentials", _SECRET_BY_KIND
    )


def downgrade() -> None:
    connection = op.get_bind()
    if connection.execute(sa.text("SELECT 1 FROM credentials WHERE kind <> 'ssh' LIMIT 1")).first():
        raise RuntimeError("Environment-variable credentials exist: delete them before downgrading")
    op.drop_constraint(op.f("ck_credentials_secret_by_kind"), "credentials", type_="check")
    op.drop_constraint(op.f("ck_credentials_kind"), "credentials", type_="check")
    op.create_check_constraint(
        op.f("ck_credentials_one_secret"),
        "credentials",
        "(encrypted_private_key IS NULL) <> (store_path IS NULL)",
    )
    op.create_check_constraint(
        op.f("ck_credentials_store_ref"),
        "credentials",
        "(store_path IS NULL) = (store_key IS NULL)",
    )
    op.drop_column("credentials", "env_names")
    op.drop_column("credentials", "encrypted_env")
    op.drop_column("credentials", "kind")
    op.drop_column("runs", "inventory_sha256")
    op.drop_column("runs", "inventory_static")
