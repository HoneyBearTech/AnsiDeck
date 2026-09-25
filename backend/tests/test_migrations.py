from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from app.db import Base, alembic_config, get_engine
from tests.conftest import TEST_DATABASE_URL


def test_the_migrations_build_exactly_the_models_schema() -> None:
    """The session fixture built the test database by running every migration; a model
    change without a matching migration shows up here as a difference."""
    with get_engine().connect() as conn:
        context = MigrationContext.configure(conn, opts={"compare_type": True})
        assert compare_metadata(context, Base.metadata) == []


def test_the_database_is_at_the_single_head_revision() -> None:
    heads = ScriptDirectory.from_config(alembic_config()).get_heads()
    assert len(heads) == 1  # no unmerged branches
    with get_engine().connect() as conn:
        assert MigrationContext.configure(conn).get_current_revision() == heads[0]


def test_0002_upgrades_existing_data_and_downgrades() -> None:
    """0002 on a database that already holds 0001-era runs: timestamps are backfilled,
    nothing is invented, and the downgrade restores the 0001 shape."""
    url = make_url(TEST_DATABASE_URL)
    scratch = url.database.removesuffix("_test") + "_migration_test"
    admin = create_engine(url.set(database="postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f'DROP DATABASE IF EXISTS "{scratch}" WITH (FORCE)'))
        conn.execute(text(f'CREATE DATABASE "{scratch}"'))
    engine = create_engine(url.set(database=scratch))
    config = alembic_config()

    def migrate(step, revision: str) -> None:
        with engine.begin() as conn:
            config.attributes["connection"] = conn
            step(config, revision)

    try:
        migrate(command.upgrade, "0001")
        with engine.begin() as conn:
            conn.execute(text("INSERT INTO projects (name, description) VALUES ('P', '')"))
            conn.execute(
                text(
                    "INSERT INTO runs (project_id, playbook_name, inventory_name, "
                    "credential_name, become, check_mode, diff_mode, status, triggered_by, "
                    "started_at, finished_at, created_at) VALUES "
                    "(1, 'pb', 'inv', 'c', false, false, false, 'success', 'a', "
                    "'2026-01-02 10:00:05+00', '2026-01-02 10:01:00+00', '2026-01-02 10:00:00+00'),"
                    "(1, 'pb', 'inv', 'c', false, false, false, 'queued', 'a', "
                    "NULL, NULL, '2026-01-03 09:00:00+00')"
                )
            )

        migrate(command.upgrade, "0002")
        with engine.connect() as conn:
            rows = conn.execute(
                text(
                    "SELECT queued_at = created_at, claimed_at IS NOT DISTINCT FROM started_at, "
                    "attempt, worker_id, hosts_total FROM runs ORDER BY id"
                )
            ).all()
            assert [tuple(r) for r in rows] == [(True, True, 1, None, None)] * 2
            indexes = set(
                conn.execute(
                    text("SELECT indexname FROM pg_indexes WHERE tablename = 'audit_events'")
                ).scalars()
            )
            assert "ix_audit_events_action_created_at" in indexes
            assert "ix_audit_events_action" not in indexes

        migrate(command.downgrade, "0001")
        with engine.connect() as conn:
            columns = set(
                conn.execute(
                    text(
                        "SELECT column_name FROM information_schema.columns "
                        "WHERE table_name = 'runs'"
                    )
                ).scalars()
            )
            assert columns.isdisjoint({"queued_at", "claimed_at", "worker_id", "attempt"})
            assert conn.execute(text("SELECT count(*) FROM runs")).scalar() == 2
    finally:
        engine.dispose()
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{scratch}" WITH (FORCE)'))
        admin.dispose()


def test_the_queue_indexes_have_their_predicates() -> None:
    """Alembic doesn't compare partial-index predicates, so a model change there would go
    unnoticed by the schema test above."""
    with get_engine().connect() as conn:
        definitions = dict(
            conn.execute(
                text("SELECT indexname, indexdef FROM pg_indexes WHERE tablename = 'runs'")
            ).all()
        )
    running = "WHERE ((status)::text = 'running'::text)"
    assert definitions["ux_runs_running_inventory"].startswith("CREATE UNIQUE INDEX")
    assert definitions["ux_runs_running_inventory"].endswith(f"(inventory_id) {running}")
    assert definitions["ix_runs_queue"].endswith(
        "(queued_at, id) WHERE ((status)::text = 'queued'::text)"
    )
    assert definitions["ix_runs_lease"].endswith(f"(lease_expires_at) {running}")


def test_0003_fails_what_the_old_engine_left_unfinished_and_downgrades() -> None:
    url = make_url(TEST_DATABASE_URL)
    scratch = url.database.removesuffix("_test") + "_migration_test"
    admin = create_engine(url.set(database="postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f'DROP DATABASE IF EXISTS "{scratch}" WITH (FORCE)'))
        conn.execute(text(f'CREATE DATABASE "{scratch}"'))
    engine = create_engine(url.set(database=scratch))
    config = alembic_config()

    def migrate(step, revision: str) -> None:
        with engine.begin() as conn:
            config.attributes["connection"] = conn
            step(config, revision)

    try:
        migrate(command.upgrade, "0002")
        with engine.begin() as conn:
            conn.execute(text("INSERT INTO projects (name, description) VALUES ('P', '')"))
            for status in ("success", "queued", "running", "running"):
                conn.execute(
                    text(
                        "INSERT INTO runs (project_id, playbook_name, inventory_name, "
                        "credential_name, become, check_mode, diff_mode, status, triggered_by) "
                        "VALUES (1, 'pb', 'inv', 'c', false, false, false, :s, 'a')"
                    ),
                    {"s": status},
                )
            conn.execute(
                text(
                    "INSERT INTO galaxy_installs (status, triggered_by, requirements_snapshot, "
                    "upgrade) VALUES ('running', 'a', 'x', false)"
                )
            )

        migrate(command.upgrade, "0003")
        with engine.connect() as conn:
            rows = conn.execute(
                text(
                    "SELECT status, status_reason, finished_at IS NOT NULL, timeout_seconds, "
                    "log_seq FROM runs ORDER BY id"
                )
            ).all()
            reason = "interrupted: never finished before the job-queue upgrade"
            assert [tuple(r) for r in rows] == [
                ("success", None, False, 7200, 0),
                ("failed", reason, True, 7200, 0),
                ("failed", reason, True, 7200, 0),
                ("failed", reason, True, 7200, 0),
            ]
            install = conn.execute(text("SELECT status, status_reason FROM galaxy_installs"))
            assert tuple(install.one()) == ("failed", reason)

        with engine.begin() as conn:
            conn.execute(text("UPDATE runs SET status = 'cancelled' WHERE id = 2"))
            conn.execute(text("UPDATE runs SET status = 'timed_out' WHERE id = 3"))
        migrate(command.downgrade, "0002")
        with engine.connect() as conn:
            statuses = conn.execute(text("SELECT status FROM runs ORDER BY id")).scalars().all()
            assert statuses == ["success", "failed", "failed", "failed"]
            columns = set(
                conn.execute(
                    text(
                        "SELECT column_name FROM information_schema.columns "
                        "WHERE table_name = 'runs'"
                    )
                ).scalars()
            )
            assert columns.isdisjoint({"playbook_snapshot", "claim_token_hash", "log_seq"})
    finally:
        engine.dispose()
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{scratch}" WITH (FORCE)'))
        admin.dispose()
