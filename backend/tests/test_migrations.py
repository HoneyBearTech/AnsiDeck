import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError

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


def test_0008_creates_the_analytics_views_and_downgrades_cleanly() -> None:
    """The downgrade removes the schema, its views, the default privileges analytics-grant
    set on it, and the index; upgrading again works."""
    url = make_url(TEST_DATABASE_URL)
    scratch = url.database.removesuffix("_test") + "_migration_test"
    role = "ansideck_analytics_migration_test"
    admin = create_engine(url.set(database="postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f'DROP DATABASE IF EXISTS "{scratch}" WITH (FORCE)'))
        conn.execute(text(f'CREATE DATABASE "{scratch}"'))
        if conn.execute(text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": role}).first():
            conn.execute(text(f"DROP ROLE {role}"))
        conn.execute(text(f"CREATE ROLE {role} NOLOGIN"))
    engine = create_engine(url.set(database=scratch))
    config = alembic_config()

    def migrate(step, revision: str) -> None:
        with engine.begin() as conn:
            config.attributes["connection"] = conn
            step(config, revision)

    def analytics_state(conn) -> tuple[int, int, bool]:
        views = conn.execute(
            text("SELECT count(*) FROM pg_views WHERE schemaname = 'analytics'")
        ).scalar()
        default_acls = conn.execute(
            text(
                "SELECT count(*) FROM pg_default_acl d "
                "JOIN pg_namespace n ON n.oid = d.defaclnamespace WHERE n.nspname = 'analytics'"
            )
        ).scalar()
        index = conn.execute(
            text("SELECT 1 FROM pg_indexes WHERE indexname = 'ix_runs_finished_at'")
        ).first()
        return views, default_acls, index is not None

    try:
        migrate(command.upgrade, "0008")
        with engine.begin() as conn:
            grant = f"GRANT SELECT ON TABLES TO {role}"
            conn.execute(text(f"ALTER DEFAULT PRIVILEGES IN SCHEMA analytics {grant}"))
            conn.execute(text(f"GRANT USAGE ON SCHEMA analytics TO {role}"))
            assert analytics_state(conn) == (9, 1, True)

        migrate(command.downgrade, "0007")
        with engine.connect() as conn:
            assert analytics_state(conn) == (0, 0, False)
            assert not conn.execute(
                text("SELECT 1 FROM pg_namespace WHERE nspname = 'analytics'")
            ).first()

        migrate(command.upgrade, "0008")
        with engine.connect() as conn:
            assert analytics_state(conn) == (9, 0, True)
    finally:
        engine.dispose()
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{scratch}" WITH (FORCE)'))
            conn.execute(text(f"DROP ROLE IF EXISTS {role}"))
        admin.dispose()


def test_0009_adds_git_sources_and_downgrades_with_the_0008_view() -> None:
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

    def view_columns(conn) -> list[str]:
        return list(
            conn.execute(
                text(
                    "SELECT column_name FROM information_schema.columns WHERE "
                    "table_schema = 'analytics' AND table_name = 'runs' ORDER BY ordinal_position"
                )
            ).scalars()
        )

    try:
        migrate(command.upgrade, "0009")
        with engine.connect() as conn:
            assert view_columns(conn)[-2:] == ["git_source_name", "git_commit"]
            assert conn.execute(text("SELECT to_regclass('git_sources')")).scalar()
        migrate(command.downgrade, "0008")
        with engine.connect() as conn:
            assert view_columns(conn)[-1] == "hosts_unreachable"
            assert conn.execute(text("SELECT to_regclass('git_sources')")).scalar() is None
            playbook_columns = set(
                conn.execute(
                    text(
                        "SELECT column_name FROM information_schema.columns "
                        "WHERE table_name = 'playbooks'"
                    )
                ).scalars()
            )
            assert "source_id" not in playbook_columns
        migrate(command.upgrade, "0009")
    finally:
        engine.dispose()
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{scratch}" WITH (FORCE)'))
        admin.dispose()


def test_0011_gives_credentials_a_kind_and_refuses_to_drop_env_credentials() -> None:
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

    def insert(conn, columns: str, values: str) -> None:
        conn.execute(text(f"INSERT INTO credentials (name, project_id, {columns}) VALUES {values}"))

    try:
        migrate(command.upgrade, "0010")
        with engine.begin() as conn:
            conn.execute(text("INSERT INTO projects (name, description) VALUES ('P', '')"))
            insert(conn, "encrypted_private_key", "('old', 1, 'x')")
        migrate(command.upgrade, "0011")
        with engine.begin() as conn:
            assert conn.execute(text("SELECT kind FROM credentials")).scalar() == "ssh"
            insert(conn, "kind, encrypted_env, env_names", "('env', 1, 'env', 'x', '[\"T\"]')")
            insert(conn, "kind, store_path", "('env-ref', 1, 'env', 'web/netbox')")
        for columns, values in [
            ("kind, encrypted_private_key", "('bad1', 1, 'env', 'x')"),  # a key in an env one
            ("kind, store_path, store_key", "('bad2', 1, 'env', 'p', 'k')"),
            ("kind, encrypted_private_key, encrypted_env", "('bad3', 1, 'ssh', 'x', 'y')"),
            ("kind, encrypted_env", "('bad4', 1, 'other', 'x')"),
        ]:
            with engine.begin() as conn, pytest.raises(IntegrityError):
                insert(conn, columns, values)
        with pytest.raises(RuntimeError, match="Environment-variable credentials exist"):
            migrate(command.downgrade, "0010")
        with engine.begin() as conn:
            conn.execute(text("DELETE FROM credentials WHERE kind = 'env'"))
        migrate(command.downgrade, "0010")
        with engine.connect() as conn:
            assert conn.execute(text("SELECT name FROM credentials")).scalars().all() == ["old"]
        migrate(command.upgrade, "0011")
    finally:
        engine.dispose()
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{scratch}" WITH (FORCE)'))
        admin.dispose()


def test_0012_adds_inventory_sources_and_downgrades_cleanly() -> None:
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

    def exists(conn, name: str) -> bool:
        return conn.execute(text("SELECT to_regclass(:n)"), {"n": name}).scalar() is not None

    try:
        migrate(command.upgrade, "0012")
        with engine.connect() as conn:
            for table in ("inventory_sources", "inventory_refreshes", "inventory_snapshots"):
                assert exists(conn, table)
            assert exists(conn, "analytics.inventory_refreshes")
        migrate(command.downgrade, "0011")
        with engine.connect() as conn:
            assert not exists(conn, "inventory_snapshots")
            assert not exists(conn, "analytics.inventory_refreshes")
        migrate(command.upgrade, "0012")
    finally:
        engine.dispose()
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{scratch}" WITH (FORCE)'))
        admin.dispose()


def test_0016_links_existing_keys_to_their_creator_by_username_and_downgrades() -> None:
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
        migrate(command.upgrade, "0015")
        with engine.begin() as conn:
            conn.execute(text("INSERT INTO projects (name, description) VALUES ('P', '')"))
            conn.execute(
                text(
                    "INSERT INTO users (username, password_hash, role, is_active, session_version) "
                    "VALUES ('bob', 'x', 'admin', true, 0)"
                )
            )
            for name, creator in (("ci", "bob"), ("orphan", "gone")):
                conn.execute(
                    text(
                        "INSERT INTO api_keys (project_id, name, preset, prefix, token_hash, "
                        "created_by, expires_at) VALUES (1, :name, 'trigger', :name, 'h', "
                        ":creator, now() + interval '1 day')"
                    ),
                    {"name": name, "creator": creator},
                )
        migrate(command.upgrade, "0016")
        with engine.connect() as conn:
            linked = dict(conn.execute(text("SELECT name, created_by_id FROM api_keys")).all())
            bob = conn.execute(text("SELECT id FROM users WHERE username = 'bob'")).scalar()
        assert linked == {"ci": bob, "orphan": None}  # a creator already gone stays unlinked
        with engine.begin() as conn:
            conn.execute(text("DELETE FROM users WHERE username = 'bob'"))
            assert conn.execute(text("SELECT count(*) FROM api_keys")).scalar() == 2  # kept
        migrate(command.downgrade, "0015")
        migrate(command.upgrade, "0016")
    finally:
        engine.dispose()
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{scratch}" WITH (FORCE)'))
        admin.dispose()


def test_0018_keeps_the_snapshot_a_run_used_and_downgrades() -> None:
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
        migrate(command.upgrade, "0017")
        with engine.begin() as conn:
            conn.execute(text("INSERT INTO projects (name, description) VALUES ('P', '')"))
            conn.execute(text("INSERT INTO inventories (project_id, name) VALUES (1, 'inv')"))
            conn.execute(
                text(
                    "INSERT INTO inventory_snapshots (inventory_id, data, sha256, host_count, "
                    "group_count, warnings, sources, created_at) VALUES (1, '{}', 'x', 12, 3, "
                    "'[]', '[]', '2026-10-01T10:00:00Z')"
                )
            )
            for snapshot in (1, None):
                conn.execute(
                    text(
                        "INSERT INTO runs (project_id, playbook_name, inventory_name, "
                        "credential_name, become, check_mode, diff_mode, status, triggered_by, "
                        "inventory_snapshot_id) "
                        "VALUES (1, 'pb', 'inv', 'c', false, false, false, 'success', 'a', :s)"
                    ),
                    {"s": snapshot},
                )
        migrate(command.upgrade, "0018")
        with engine.connect() as conn:
            rows = conn.execute(
                text(
                    "SELECT to_char(inventory_snapshot_at AT TIME ZONE 'UTC', "
                    "'YYYY-MM-DD HH24:MI'), inventory_snapshot_hosts FROM runs ORDER BY id"
                )
            ).all()
        assert [tuple(r) for r in rows] == [("2026-10-01 10:00", 12), (None, None)]
        migrate(command.downgrade, "0017")
        migrate(command.upgrade, "0018")
    finally:
        engine.dispose()
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{scratch}" WITH (FORCE)'))
        admin.dispose()


def test_0020_leaves_existing_inventories_unchecked_and_downgrades() -> None:
    """Existing inventories keep today's behaviour (no host key checking); new ones check."""
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
        migrate(command.upgrade, "0019")
        with engine.begin() as conn:
            conn.execute(text("INSERT INTO projects (name, description) VALUES ('P', '')"))
            conn.execute(text("INSERT INTO inventories (project_id, name) VALUES (1, 'old')"))
        migrate(command.upgrade, "0020")
        with engine.begin() as conn:
            conn.execute(text("INSERT INTO inventories (project_id, name) VALUES (1, 'new')"))
            modes = conn.execute(
                text("SELECT name, host_key_checking FROM inventories ORDER BY id")
            ).all()
            conn.execute(
                text(
                    "INSERT INTO inventory_host_keys (inventory_id, name, key_type, key_b64, "
                    "fingerprint, source, created_by) VALUES (1, 'web1', 'ssh-ed25519', 'AAAA', "
                    "'SHA256:x', 'paste', 'admin')"
                )
            )
            # One key per name and type.
            with pytest.raises(IntegrityError), conn.begin_nested():
                conn.execute(
                    text(
                        "INSERT INTO inventory_host_keys (inventory_id, name, key_type, "
                        "key_b64, fingerprint, source, created_by) VALUES (1, 'web1', "
                        "'ssh-ed25519', 'BBBB', 'SHA256:y', 'paste', 'admin')"
                    )
                )
        assert [tuple(r) for r in modes] == [("old", "off"), ("new", "accept_new")]
        migrate(command.downgrade, "0019")
        migrate(command.upgrade, "0020")
    finally:
        engine.dispose()
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{scratch}" WITH (FORCE)'))
        admin.dispose()


def test_0028_adds_ssh_certificate_credentials_and_refuses_to_drop_them() -> None:
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

    def insert(conn, columns: str, values: str) -> None:
        conn.execute(text(f"INSERT INTO credentials (name, project_id, {columns}) VALUES {values}"))

    try:
        migrate(command.upgrade, "0027")
        with engine.begin() as conn:
            conn.execute(text("INSERT INTO projects (name, description) VALUES ('P', '')"))
            insert(conn, "encrypted_private_key", "('old', 1, 'x')")
        migrate(command.upgrade, "0028")
        with engine.begin() as conn:
            insert(
                conn,
                "kind, ssh_mount, ssh_role, ssh_principals",
                "('cert', 1, 'ssh_cert', 'ssh', 'web', '[\"deploy\"]')",
            )
        for columns, values in [
            ("kind, ssh_mount, ssh_role", "('bad1', 1, 'ssh_cert', 'ssh', 'web')"),  # no users
            (  # a key in a certificate one
                "kind, encrypted_private_key, ssh_mount, ssh_role, ssh_principals",
                "('bad2', 1, 'ssh_cert', 'x', 'ssh', 'web', '[\"d\"]')",
            ),
            (
                "kind, store_path, store_key, ssh_mount, ssh_role, ssh_principals",
                "('bad3', 1, 'ssh_cert', 'p', 'k', 'ssh', 'web', '[\"d\"]')",
            ),
            ("encrypted_private_key, ssh_role", "('bad4', 1, 'x', 'web')"),  # a role on a key
            ("kind, encrypted_env, ssh_mount", "('bad5', 1, 'env', 'x', 'ssh')"),
        ]:
            with engine.begin() as conn, pytest.raises(IntegrityError):
                insert(conn, columns, values)
        with pytest.raises(RuntimeError, match="SSH certificate credentials exist"):
            migrate(command.downgrade, "0027")
        with engine.begin() as conn:
            conn.execute(text("DELETE FROM credentials WHERE kind = 'ssh_cert'"))
        migrate(command.downgrade, "0027")
        with engine.begin() as conn:
            assert conn.execute(text("SELECT name FROM credentials")).scalars().all() == ["old"]
            with pytest.raises(IntegrityError), conn.begin_nested():
                insert(conn, "kind", "('c', 1, 'ssh_cert')")
        migrate(command.upgrade, "0028")
    finally:
        engine.dispose()
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{scratch}" WITH (FORCE)'))
        admin.dispose()
