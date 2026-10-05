"""Secret store references (Phase 4F): a credential's private key or a vault password may be a
reference into OpenBao / HashiCorp Vault (a path under the project's subtree and a key)
instead of an encrypted value. Exactly one of the two (CHECK constraints).

Revision ID: 0010
Revises: 0009
Create Date: 2026-10-04 22:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLES = (("credentials", "encrypted_private_key"), ("vault_passwords", "encrypted_password"))


def upgrade() -> None:
    for table, secret in _TABLES:
        op.alter_column(table, secret, existing_type=sa.LargeBinary(), nullable=True)
        op.add_column(table, sa.Column("store_path", sa.String(length=400), nullable=True))
        op.add_column(table, sa.Column("store_key", sa.String(length=100), nullable=True))
        op.create_check_constraint(
            op.f(f"ck_{table}_one_secret"), table, f"({secret} IS NULL) <> (store_path IS NULL)"
        )
        op.create_check_constraint(
            op.f(f"ck_{table}_store_ref"), table, "(store_path IS NULL) = (store_key IS NULL)"
        )


def downgrade() -> None:
    connection = op.get_bind()
    for table, _ in _TABLES:
        if connection.execute(
            sa.text(f"SELECT 1 FROM {table} WHERE store_path IS NOT NULL LIMIT 1")  # noqa: S608 - constants and quoted identifiers only
        ).first():
            raise RuntimeError(
                f"{table} has secret store references; delete them (or move the secrets into "
                "AnsiDeck) before downgrading below 0010"
            )
    for table, secret in _TABLES:
        op.drop_constraint(op.f(f"ck_{table}_store_ref"), table, type_="check")
        op.drop_constraint(op.f(f"ck_{table}_one_secret"), table, type_="check")
        op.drop_column(table, "store_key")
        op.drop_column(table, "store_path")
        op.alter_column(table, secret, existing_type=sa.LargeBinary(), nullable=False)
