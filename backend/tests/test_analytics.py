"""The read-only analytics schema (migration 0008) and the grant/check/revoke commands: a
granted role reads the curated views and nothing else, and the views leave out secrets."""

import re
from collections.abc import Generator
from datetime import UTC, datetime, timedelta

import pytest
from psycopg.errors import InsufficientPrivilege
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError

from app import analytics, cli
from app.db import Base, get_engine, get_sessionmaker
from app.models import ApiKey, AuditEvent, Project, Run, User

ROLE = "ansideck_analytics_test"

COLUMNS = {
    "api_keys": [
        "api_key_id", "project_id", "name", "preset", "created_by", "created_at",
        "expires_at", "last_used_at", "revoked_at", "revoked_by", "state",
    ],
    "audit_events": [
        "event_id", "created_at", "action", "outcome", "actor_username", "actor_kind",
        "project_id", "target_type", "target_id", "target_name", "reason",
        "required_permission", "login_method", "locked_out", "client_network",
    ],
    "galaxy_installs": [
        "install_id", "status", "status_reason", "upgrade", "return_code", "triggered_by",
        "created_at", "started_at", "finished_at", "run_seconds",
    ],
    "inventory_refreshes": [
        "refresh_id", "project_id", "inventory_id", "status", "trigger", "queued_at",
        "started_at", "finished_at", "duration_seconds", "worker", "host_count", "group_count",
    ],
    "notification_deliveries": [
        "delivery_id", "channel_id", "channel", "kind", "project_id", "event", "status",
        "attempts", "last_status_code", "created_at", "sent_at",
    ],
    "ops_alerts": ["kind", "subject", "raised_at"],
    "projects": ["project_id", "project", "created_at"],
    "runs": [
        "run_id", "project_id", "project", "playbook_id", "playbook_name", "inventory_id",
        "inventory_name", "group_name", "status", "status_reason", "return_code",
        "check_mode", "diff_mode", "become", "triggered_by", "via_api_key", "attempt",
        "worker", "cancel_requested", "timeout_seconds", "created_at", "queued_at",
        "claimed_at", "started_at", "finished_at", "queue_wait_seconds", "run_seconds",
        "total_seconds", "hosts_total", "hosts_ok", "hosts_changed", "hosts_failed",
        "hosts_unreachable", "git_source_name", "git_commit",
    ],
    "user_summary": ["role", "active", "sso_linked", "two_factor", "users"],
    "workers": [
        "worker", "slots", "isolated", "first_seen_at", "last_seen_at", "online", "running",
    ],
}  # fmt: skip
# Nothing named like a secret, a hash, raw output or a full address may reach Grafana.
DENIED = re.compile(
    r"extra_vars|payload|detail|token|hash|password|secret|encrypted|snapshot|limit|error|"
    r"totp|recovery|config|^ip$|_ip$|email|sso_subject|log_"
)


def _drop_role(conn, role: str) -> None:
    if conn.execute(text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": role}).first():
        conn.execute(text(f"DROP OWNED BY {role}"))  # its grants and default privileges here
        conn.execute(text(f"DROP ROLE {role}"))


@pytest.fixture
def role(client) -> Generator[str, None, None]:
    with get_engine().begin() as conn:
        _drop_role(conn, ROLE)
        conn.execute(text(f"CREATE ROLE {ROLE} NOLOGIN"))
    yield ROLE
    with get_engine().begin() as conn:
        _drop_role(conn, ROLE)


@pytest.fixture
def db():
    session = get_sessionmaker()()
    yield session
    session.close()


def as_role(sql: str, role: str = ROLE, **params):
    """Runs one statement as `role` (SET ROLE, like a Grafana connection would log in)."""
    with get_engine().connect() as conn:
        conn.execute(text(f"SET ROLE {role}"))
        try:
            return conn.execute(text(sql), params).all()
        finally:
            conn.rollback()


def denied(sql: str) -> bool:
    try:
        as_role(sql)
    except ProgrammingError as exc:
        return isinstance(exc.orig, InsufficientPrivilege)
    return False


def test_the_views_are_exactly_the_curated_columns(client, db) -> None:
    rows = db.execute(
        text(
            "SELECT table_name, column_name FROM information_schema.columns "
            "WHERE table_schema = 'analytics' ORDER BY table_name, ordinal_position"
        )
    ).all()
    found: dict[str, list[str]] = {}
    for view, column in rows:
        found.setdefault(view, []).append(column)
    assert found == COLUMNS
    leaky = [f"{v}.{c}" for v, cols in found.items() for c in cols if DENIED.search(c)]
    assert leaky == []
    assert analytics.view_names(db) == sorted(COLUMNS)


def test_a_granted_role_reads_the_views_and_no_table(role, db) -> None:
    assert denied("SELECT 1 FROM analytics.runs")  # nothing before the grant
    result = analytics.grant(db, role)
    assert result.ok, result.problems
    for view in COLUMNS:
        as_role(f"SELECT * FROM analytics.{view} LIMIT 1")
    for table in Base.metadata.sorted_tables:
        assert denied(f'SELECT 1 FROM public."{table.name}" LIMIT 1'), table.name
    assert denied("SELECT 1 FROM public.alembic_version")
    assert denied("INSERT INTO analytics.projects (project_id, project) VALUES (99, 'x')")
    assert denied("UPDATE analytics.projects SET project = 'x'")  # single-table: updatable
    assert denied("DELETE FROM analytics.audit_events")
    assert denied("CREATE TABLE public.sneaky (x int)")
    assert denied("CREATE VIEW analytics.sneaky AS SELECT 1")


def test_views_added_later_are_readable_too(role, db) -> None:
    analytics.grant(db, role)
    db.execute(text("CREATE VIEW analytics.zz_later AS SELECT 1 AS x"))
    db.commit()
    try:
        assert as_role("SELECT x FROM analytics.zz_later") == [(1,)]
    finally:
        db.execute(text("DROP VIEW analytics.zz_later"))
        db.commit()


def test_check_finds_what_a_role_must_not_have(role, db) -> None:
    analytics.grant(db, role)
    clean = analytics.check(db, role)
    assert clean.ok
    assert any("default_transaction_read_only" in w for w in clean.warnings)
    assert any("temporary" in w for w in clean.warnings)

    with get_engine().begin() as conn:
        conn.execute(text(f"GRANT SELECT (username) ON public.users TO {role}"))
        conn.execute(text(f"GRANT CREATE ON SCHEMA public TO {role}"))
        conn.execute(text(f"GRANT INSERT ON analytics.projects TO {role}"))
        conn.execute(text(f"ALTER ROLE {role} CREATEDB"))
        conn.execute(text(f"ALTER ROLE {role} SET default_transaction_read_only = on"))
    result = analytics.check(db, role)
    assert set(result.problems) == {
        "the role has CREATEDB",
        "the role has privileges on public.users",
        "the role may change analytics.projects",
        "the role may create objects in schema public",
    }
    assert not any("default_transaction_read_only" in w for w in result.warnings)
    with get_engine().begin() as conn:
        conn.execute(text(f"REVOKE CREATE ON SCHEMA public FROM {role}"))


def test_revoke_takes_the_access_away(role, db) -> None:
    analytics.grant(db, role)
    analytics.revoke(db, role)
    assert denied("SELECT 1 FROM analytics.runs")
    result = analytics.check(db, role)
    assert "the role has no USAGE on the analytics schema" in result.problems
    assert "the role can't read analytics.runs" in result.problems
    assert not db.execute(
        text(
            "SELECT 1 FROM pg_default_acl d JOIN pg_namespace n ON n.oid = d.defaclnamespace "
            "WHERE n.nspname = 'analytics' AND d.defaclacl::text LIKE :r"
        ),
        {"r": f"%{role}%"},
    ).first()


def test_grant_refuses_roles_that_would_see_everything_anyway(role, db) -> None:
    with pytest.raises(analytics.AnalyticsError, match="no database role"):
        analytics.grant(db, "no_such_role_zq")
    me = db.execute(text("SELECT current_user")).scalar()
    with pytest.raises(analytics.AnalyticsError):  # (a superuser in the test database)
        analytics.grant(db, me)
    with get_engine().begin() as conn:
        conn.execute(text(f"GRANT {me} TO {role}"))
    with pytest.raises(analytics.AnalyticsError, match="app's own database user"):
        analytics.grant(db, role)
    with get_engine().begin() as conn:
        conn.execute(text(f"REVOKE {me} FROM {role}"))
        conn.execute(text(f"ALTER ROLE {role} SUPERUSER"))
    with pytest.raises(analytics.AnalyticsError, match="superuser"):
        analytics.grant(db, role)
    with get_engine().begin() as conn:
        conn.execute(text(f"ALTER ROLE {role} NOSUPERUSER"))


def test_the_cli_grants_checks_and_revokes(role, capsys) -> None:
    assert cli.main(["analytics-grant", role]) == 0
    assert "can read the analytics views and nothing else" in capsys.readouterr().out
    assert cli.main(["analytics-check", role]) == 0
    assert cli.main(["analytics-check", "no_such_role_zq"]) == 1
    assert "no database role" in capsys.readouterr().err
    assert cli.main(["analytics-revoke", role]) == 0
    assert cli.main(["analytics-check", role]) == 1
    assert "not limited to reading the analytics views" in capsys.readouterr().err


def test_audit_events_show_networks_and_allowlisted_details_only(role, db) -> None:
    analytics.grant(db, role)
    now = datetime.now(UTC)
    events = [
        (
            "auth.login",
            "failure",
            "203.0.113.77",
            {"reason": "bad credentials", "locked_out": True},
        ),
        ("auth.login", "failure", "2001:db8:abcd:12::1", {"reason": "my password is hunter2"}),
        ("auth.login", "success", "testclient", {"mfa": "totp"}),
        ("auth.login", "success", None, {"method": "github"}),
        ("permission.denied", "denied", "10.1.2.3", {"required": "runs:trigger", "api_key_id": 4}),
        ("run.trigger", "success", "10.1.2.3", {"extra": "hunter2-in-detail"}),
    ]
    for action, outcome, ip, detail in events:
        db.add(
            AuditEvent(
                action=action,
                outcome=outcome,
                ip=ip,
                detail=detail,
                actor_username="alice",
                created_at=now,
            )
        )
    db.commit()
    rows = as_role(
        "SELECT action, reason, required_permission, login_method, locked_out, client_network, "
        "actor_kind, actor_username FROM analytics.audit_events ORDER BY event_id"
    )
    assert [tuple(r) for r in rows] == [
        ("auth.login", "bad credentials", None, None, True, "203.0.113.0/24", "other", "alice"),
        ("auth.login", "other", None, None, False, "2001:db8:abcd::/48", "other", "alice"),
        ("auth.login", None, None, "password+totp", False, None, "other", "alice"),
        ("auth.login", None, None, "github", False, None, "other", "alice"),
        ("permission.denied", None, "runs:trigger", None, False, "10.1.2.0/24", "api_key", "alice"),
        ("run.trigger", None, None, None, False, "10.1.2.0/24", "other", "alice"),
    ]
    everything = str(as_role("SELECT * FROM analytics.audit_events"))
    assert "hunter2" not in everything
    assert "203.0.113.77" not in everything


def test_runs_show_durations_but_no_secrets(role, db) -> None:
    analytics.grant(db, role)
    project = db.query(Project).filter(Project.name == "Default").one()
    key = ApiKey(
        project_id=project.id,
        name="ci",
        preset="trigger",
        prefix="adk_zq",
        token_hash="f" * 64,
        created_by="admin",
        expires_at=datetime.now(UTC) + timedelta(days=1),
    )
    db.add(key)
    db.flush()
    t0 = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
    db.add(
        Run(
            project_id=project.id,
            playbook_name="site.yml",
            inventory_name="prod",
            credential_name="deploy-key-zq",
            vault_password_name="vault-zq",
            limit="secret-host-zq",
            extra_vars={"api_token": "sentinel-zq"},
            playbook_snapshot="- hosts: all # snapshot-zq",
            playbook_sha256="0" * 64,
            status="success",
            triggered_by="apikey:ci",
            triggered_by_api_key_id=key.id,
            queued_at=t0,
            claimed_at=t0 + timedelta(seconds=2),
            started_at=t0 + timedelta(seconds=3),
            finished_at=t0 + timedelta(seconds=63),
            claim_token_hash="c" * 64,
        )
    )
    db.commit()
    rows = as_role(
        "SELECT project, via_api_key, queue_wait_seconds, run_seconds, total_seconds "
        "FROM analytics.runs"
    )
    assert [tuple(r) for r in rows] == [("Default", True, 2.0, 60.0, 63.0)]
    assert "zq" not in str(as_role("SELECT * FROM analytics.runs"))
    assert as_role("SELECT state FROM analytics.api_keys") == [("active",)]
    assert "adk_zq" not in str(as_role("SELECT * FROM analytics.api_keys"))


def test_user_summary_is_counts_only(role, db) -> None:
    analytics.grant(db, role)
    db.add(User(username="bob-zq", password_hash="x", role="viewer", totp_secret=b"s"))
    db.commit()
    rows = as_role("SELECT role, active, sso_linked, two_factor, users FROM analytics.user_summary")
    assert sorted(tuple(r) for r in rows) == [
        ("admin", True, False, False, 1),
        ("viewer", True, False, True, 1),
    ]


def test_time_filters_on_runs_still_use_the_index(client, db) -> None:
    """security_barrier must not stop Grafana's time-range filter reaching the index."""
    db.execute(text("SET LOCAL enable_seqscan = off"))
    plan = "\n".join(
        db.execute(
            text(
                "EXPLAIN SELECT * FROM analytics.runs WHERE finished_at > now() - interval '7 days'"
            )
        ).scalars()
    )
    db.rollback()
    assert "ix_runs_finished_at" in plan, plan
