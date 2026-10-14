"""Passkeys (WebAuthn) as a second factor beside TOTP: the credentials, each user's stable
WebAuthn handle and pending challenge. The analytics view of audit events learns the passkey
login method and the new refusal reasons.

Revision ID: 0026
Revises: 0025
Create Date: 2026-10-15 15:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0026"
down_revision: str | None = "0025"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# 0008's reasons, and those added since.
_REASONS_0008 = (
    "bad credentials",
    "inactive",
    "bad second factor",
    "wrong current password",
    "malformed",
    "unknown key",
    "bad secret",
    "expired",
    "revoked",
    "failed",
    "not_linked",
    "api keys cannot use this endpoint",
    "api keys may only cancel their own runs",
)
_REASONS_0026 = (*_REASONS_0008, "address not allowed", "two-factor setup required")


def _audit_events(reasons: tuple[str, ...], mfa: tuple[str, ...]) -> str:
    return f"""
        SELECT a.id AS event_id, a.created_at, a.action, a.outcome,
               a.actor_username,
               CASE
                   WHEN a.detail ->> 'api_key_id' IS NOT NULL
                        OR a.actor_username LIKE 'apikey:%'
                        OR a.actor_username = '(malformed key)' THEN 'api_key'
                   WHEN a.actor_user_id IS NOT NULL THEN 'user'
                   WHEN a.actor_username IS NULL THEN 'system'
                   ELSE 'other'
               END AS actor_kind,
               a.project_id, a.target_type, a.target_id, a.target_name,
               CASE
                   WHEN a.detail ->> 'reason' IN ({", ".join(f"'{r}'" for r in reasons)})
                       THEN a.detail ->> 'reason'
                   WHEN a.detail ->> 'reason' IS NOT NULL THEN 'other'
               END AS reason,
               CASE WHEN a.detail ->> 'required' ~ '^[a-z_]+:[a-z_]+$'
                    THEN a.detail ->> 'required' END AS required_permission,
               CASE WHEN a.action = 'auth.login' AND a.outcome = 'success' THEN
                   CASE
                       WHEN a.detail ->> 'method' IN ('sso', 'github') THEN a.detail ->> 'method'
                       WHEN a.detail ->> 'mfa' IN ({", ".join(f"'{m}'" for m in mfa)})
                           THEN 'password+' || (a.detail ->> 'mfa')
                       ELSE 'password'
                   END
               END AS login_method,
               coalesce(a.detail ->> 'locked_out' = 'true', false) AS locked_out,
               CASE WHEN pg_input_is_valid(a.ip, 'inet') THEN
                   CASE WHEN family(a.ip::inet) = 4
                        THEN network(set_masklen(a.ip::inet, 24))::text
                        ELSE network(set_masklen(a.ip::inet, 48))::text
                   END
               END AS client_network
        FROM public.audit_events a
    """  # noqa: S608 - constants only


def upgrade() -> None:
    op.create_table(
        "webauthn_credentials",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("credential_id", sa.String(length=1400), nullable=False),
        sa.Column("public_key", sa.Text(), nullable=False),
        sa.Column("sign_count", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column("transports", sa.JSON(), nullable=True),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("aaguid", sa.String(length=36), nullable=True),
        sa.Column("backup_eligible", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("backed_up", sa.Boolean(), server_default="false", nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_webauthn_credentials_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_webauthn_credentials")),
        sa.UniqueConstraint("credential_id", name=op.f("uq_webauthn_credentials_credential_id")),
        sa.UniqueConstraint("user_id", "name", name="uq_webauthn_credential_user_name"),
    )
    op.create_index(op.f("ix_webauthn_credentials_user_id"), "webauthn_credentials", ["user_id"])
    op.add_column("users", sa.Column("webauthn_user_handle", sa.String(length=64), nullable=True))
    op.add_column("users", sa.Column("webauthn_pending", sa.JSON(), nullable=True))
    op.execute(
        "CREATE OR REPLACE VIEW analytics.audit_events WITH (security_barrier) AS "
        + _audit_events(_REASONS_0026, ("totp", "recovery_code", "passkey"))
    )


def downgrade() -> None:
    op.execute(
        "CREATE OR REPLACE VIEW analytics.audit_events WITH (security_barrier) AS "
        + _audit_events(_REASONS_0008, ("totp", "recovery_code"))
    )
    op.drop_column("users", "webauthn_pending")
    op.drop_column("users", "webauthn_user_handle")
    op.drop_table("webauthn_credentials")
