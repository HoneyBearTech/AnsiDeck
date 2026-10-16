"""Project memberships a sign-in provider manages (GitHub team mapping) record which one:
`granted_by`. NULL is a membership set by hand, which no sign-in ever changes.

Downgrading drops the column: managed memberships stay, as ordinary ones.

Revision ID: 0036
Revises: 0035
Create Date: 2026-10-16 12:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0036"
down_revision: str | None = "0035"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("project_members", sa.Column("granted_by", sa.String(length=20), nullable=True))
    op.create_check_constraint(
        op.f("ck_project_members_granted_by"),
        "project_members",
        "granted_by IN ('github', 'oidc')",
    )


def downgrade() -> None:
    op.drop_constraint(op.f("ck_project_members_granted_by"), "project_members", type_="check")
    op.drop_column("project_members", "granted_by")
