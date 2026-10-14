"""Short-lived SSH certificates for runs: a third credential kind, "ssh_cert", that holds only
the secret store's SSH engine mount, a project-local role name and the principals; the
certificate each run got; and which workers can load one.

Revision ID: 0028
Revises: 0027
Create Date: 2026-10-15 09:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0028"
down_revision: str | None = "0027"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_NO_CERT = " AND ssh_mount IS NULL AND ssh_role IS NULL AND ssh_principals IS NULL"

_SECRET_BY_KIND = (
    "CASE kind"
    " WHEN 'ssh' THEN encrypted_env IS NULL"
    " AND (encrypted_private_key IS NULL) <> (store_path IS NULL)"
    " AND (store_path IS NULL) = (store_key IS NULL)"
    f"{_NO_CERT}"
    " WHEN 'env' THEN encrypted_private_key IS NULL AND store_key IS NULL"
    " AND (encrypted_env IS NULL) <> (store_path IS NULL)"
    f"{_NO_CERT}"
    " WHEN 'ssh_cert' THEN encrypted_private_key IS NULL AND encrypted_env IS NULL"
    " AND store_path IS NULL AND store_key IS NULL"
    " AND ssh_mount IS NOT NULL AND ssh_role IS NOT NULL AND ssh_principals IS NOT NULL"
    " ELSE false END"
)

# 0011's constraints, restored on downgrade.
_OLD_SECRET_BY_KIND = (
    "CASE kind"  # noqa: S105 - column names, not secrets
    " WHEN 'ssh' THEN encrypted_env IS NULL"
    " AND (encrypted_private_key IS NULL) <> (store_path IS NULL)"
    " AND (store_path IS NULL) = (store_key IS NULL)"
    " WHEN 'env' THEN encrypted_private_key IS NULL AND store_key IS NULL"
    " AND (encrypted_env IS NULL) <> (store_path IS NULL)"
    " ELSE false END"
)


def upgrade() -> None:
    op.add_column("credentials", sa.Column("ssh_mount", sa.String(length=100), nullable=True))
    op.add_column("credentials", sa.Column("ssh_role", sa.String(length=64), nullable=True))
    op.add_column("credentials", sa.Column("ssh_principals", sa.JSON(), nullable=True))
    op.drop_constraint(op.f("ck_credentials_secret_by_kind"), "credentials", type_="check")
    op.drop_constraint(op.f("ck_credentials_kind"), "credentials", type_="check")
    op.create_check_constraint(
        op.f("ck_credentials_kind"), "credentials", "kind IN ('ssh', 'env', 'ssh_cert')"
    )
    op.create_check_constraint(
        op.f("ck_credentials_secret_by_kind"), "credentials", _SECRET_BY_KIND
    )
    op.add_column("runs", sa.Column("ssh_certificate", sa.JSON(), nullable=True))
    op.add_column("workers", sa.Column("ssh_certificates", sa.Boolean(), nullable=True))


def downgrade() -> None:
    connection = op.get_bind()
    if connection.execute(
        sa.text("SELECT 1 FROM credentials WHERE kind = 'ssh_cert' LIMIT 1")
    ).first():
        raise RuntimeError("SSH certificate credentials exist: delete them before downgrading")
    op.drop_column("workers", "ssh_certificates")
    op.drop_column("runs", "ssh_certificate")
    op.drop_constraint(op.f("ck_credentials_secret_by_kind"), "credentials", type_="check")
    op.drop_constraint(op.f("ck_credentials_kind"), "credentials", type_="check")
    op.create_check_constraint(op.f("ck_credentials_kind"), "credentials", "kind IN ('ssh', 'env')")
    op.create_check_constraint(
        op.f("ck_credentials_secret_by_kind"), "credentials", _OLD_SECRET_BY_KIND
    )
    op.drop_column("credentials", "ssh_principals")
    op.drop_column("credentials", "ssh_role")
    op.drop_column("credentials", "ssh_mount")
