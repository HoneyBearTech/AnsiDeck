"""The read-only `analytics` schema for Grafana (Phase 4H-2): curated views over the tables,
for a role that gets SELECT on these views only (`python -m app.cli analytics-grant <role>`).

The views run with their owner's rights (the app's database user), so the Grafana role needs
no privilege on any table. They leave out everything secret or sensitive: extra_vars, limits,
playbook snapshots, credential and vault names, token and password hashes, encrypted blobs,
run output and log positions, notification payloads and errors, galaxy requirements, alert
data, and audit `detail` (only an allowlisted reason, the required permission, the sign-in
method and the lockout flag come from it). Client addresses are cut to their network (/24
for IPv4, /48 for IPv6). User names are kept: the audit trail is about who did what.

security_barrier keeps a viewer's own functions from seeing rows a view filters out.

A later migration that changes or drops a column one of these views reads must drop and
recreate that view in the same migration (Postgres refuses otherwise). Grants survive that:
analytics-grant also sets default privileges for views the app creates here later.

Revision ID: 0008
Revises: 0007
Create Date: 2026-10-04 16:00:00.000000
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Audit reasons that are fixed strings in the code (anything else shows as 'other').
_REASONS = (
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

VIEWS = {
    "projects": """
        SELECT p.id AS project_id, p.name AS project, p.created_at
        FROM public.projects p
    """,
    "runs": """
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
               r.hosts_total, r.hosts_ok, r.hosts_changed, r.hosts_failed, r.hosts_unreachable
        FROM public.runs r
        JOIN public.projects p ON p.id = r.project_id
    """,
    "workers": """
        SELECT w.id AS worker, w.slots, w.isolated, w.first_seen_at, w.last_seen_at,
               w.last_seen_at > now() - interval '30 seconds' AS online,
               (SELECT count(*) FROM public.runs r
                WHERE r.status = 'running' AND r.worker_id = w.id) AS running
        FROM public.workers w
    """,
    "galaxy_installs": """
        SELECT g.id AS install_id, g.status, g.status_reason, g.upgrade, g.return_code,
               g.triggered_by, g.created_at, g.started_at, g.finished_at,
               extract(epoch FROM g.finished_at - g.started_at)::float8 AS run_seconds
        FROM public.galaxy_installs g
    """,
    "audit_events": f"""
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
                   WHEN a.detail ->> 'reason' IN ({", ".join(f"'{r}'" for r in _REASONS)})
                       THEN a.detail ->> 'reason'
                   WHEN a.detail ->> 'reason' IS NOT NULL THEN 'other'
               END AS reason,
               CASE WHEN a.detail ->> 'required' ~ '^[a-z_]+:[a-z_]+$'
                    THEN a.detail ->> 'required' END AS required_permission,
               CASE WHEN a.action = 'auth.login' AND a.outcome = 'success' THEN
                   CASE
                       WHEN a.detail ->> 'method' IN ('sso', 'github') THEN a.detail ->> 'method'
                       WHEN a.detail ->> 'mfa' IN ('totp', 'recovery_code')
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
    """,  # noqa: S608 - the reasons are constants
    "notification_deliveries": """
        SELECT d.id AS delivery_id, d.channel_id, c.name AS channel, c.kind, c.project_id,
               d.event, d.status, d.attempts, d.last_status_code, d.created_at, d.sent_at
        FROM public.notification_deliveries d
        JOIN public.notification_channels c ON c.id = d.channel_id
    """,
    "ops_alerts": """
        SELECT split_part(n.key, ':', 1) AS kind,
               nullif(substr(n.key, length(split_part(n.key, ':', 1)) + 2), '') AS subject,
               n.raised_at
        FROM public.notification_alerts n
    """,
    "api_keys": """
        SELECT k.id AS api_key_id, k.project_id, k.name, k.preset, k.created_by, k.created_at,
               k.expires_at, k.last_used_at, k.revoked_at, k.revoked_by,
               CASE WHEN k.revoked_at IS NOT NULL THEN 'revoked'
                    WHEN k.expires_at <= now() THEN 'expired'
                    ELSE 'active' END AS state
        FROM public.api_keys k
    """,
    "user_summary": """
        SELECT u.role, u.is_active AS active, u.sso_subject IS NOT NULL AS sso_linked,
               u.totp_secret IS NOT NULL AS two_factor, count(*) AS users
        FROM public.users u
        GROUP BY 1, 2, 3, 4
    """,
}


def upgrade() -> None:
    op.create_index("ix_runs_finished_at", "runs", ["finished_at"])
    op.execute("CREATE SCHEMA analytics")
    op.execute(
        "COMMENT ON SCHEMA analytics IS 'Read-only views for Grafana (AnsiDeck). Grant with: "
        "python -m app.cli analytics-grant <role>'"
    )
    for name, query in VIEWS.items():
        op.execute(f"CREATE VIEW analytics.{name} WITH (security_barrier) AS {query}")


def downgrade() -> None:
    op.execute("DROP SCHEMA analytics CASCADE")
    op.drop_index("ix_runs_finished_at", table_name="runs")
