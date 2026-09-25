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
