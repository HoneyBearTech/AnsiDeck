import hashlib
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text

from app import cli
from app.bootstrap import PendingSqliteImport, refuse_to_start_over_legacy_data, seed_fresh_install
from app.config import get_settings
from app.crypto import hash_password
from app.db import get_engine, get_sessionmaker
from app.main import app
from app.models import AuditEvent, Playbook, Project, ProjectMember, Run, User
from app.sqlite_import import ImportFailed, import_sqlite
from tests.conftest import truncate_all

# A database from before per-project separation (Phase 3 Pass B1), as SQLite held it.
OLD_SCHEMA = """
CREATE TABLE users (
  id INTEGER PRIMARY KEY, username VARCHAR(150) UNIQUE, password_hash VARCHAR(255),
  role VARCHAR(20) NOT NULL DEFAULT 'viewer', is_active BOOLEAN NOT NULL DEFAULT 1,
  session_version INTEGER NOT NULL DEFAULT 0, created_by VARCHAR(150),
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE playbooks (
  id INTEGER PRIMARY KEY, name VARCHAR(255),
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE inventories (
  id INTEGER PRIMARY KEY, name VARCHAR(255) UNIQUE, description VARCHAR(500),
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE credentials (
  id INTEGER PRIMARY KEY, name VARCHAR(150) UNIQUE, description VARCHAR(500),
  encrypted_private_key BLOB, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE vault_passwords (
  id INTEGER PRIMARY KEY, name VARCHAR(150) UNIQUE, description VARCHAR(500),
  encrypted_password BLOB, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE runs (
  id INTEGER PRIMARY KEY, playbook_id INTEGER, playbook_name VARCHAR(255) NOT NULL,
  inventory_id INTEGER, inventory_name VARCHAR(255) NOT NULL, group_id INTEGER,
  group_name VARCHAR(255), credential_id INTEGER, credential_name VARCHAR(150) NOT NULL,
  become BOOLEAN, status VARCHAR(20), triggered_by VARCHAR(150) NOT NULL, return_code INTEGER,
  started_at DATETIME, finished_at DATETIME, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE audit_events (
  id INTEGER PRIMARY KEY, created_at DATETIME, actor_user_id INTEGER,
  actor_username VARCHAR(150), action VARCHAR(64), target_type VARCHAR(50), target_id INTEGER,
  target_name VARCHAR(255), outcome VARCHAR(20), ip VARCHAR(64), detail JSON);
"""

OLD_ROWS = [
    "INSERT INTO playbooks (id, name) VALUES (1, 'old-playbook')",
    "INSERT INTO inventories (id, name) VALUES (1, 'old-inv')",
    "INSERT INTO credentials (id, name, encrypted_private_key) VALUES (1, 'old-cred', x'00')",
    "INSERT INTO vault_passwords (id, name, encrypted_password) VALUES (1, 'old-vault', x'00')",
    "INSERT INTO runs (id, playbook_id, playbook_name, inventory_id, inventory_name,"
    " credential_id, credential_name, become, status, triggered_by)"
    " VALUES (1, 1, 'old-playbook', 1, 'old-inv', 1, 'old-cred', 0, 'success', 'boss')",
    "INSERT INTO audit_events (id, action, outcome) VALUES (1, 'auth.login', 'success')",
]


@pytest.fixture
def empty(tmp_path, monkeypatch) -> Path:
    """An empty Postgres (no seeded admin) and a data dir; returns the data dir."""
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    get_settings.cache_clear()
    truncate_all()
    yield tmp_path
    get_settings.cache_clear()


def _legacy_db(directory: Path, extra: list[str] = ()) -> Path:
    path = directory / "ansideck.db"
    con = sqlite3.connect(path)
    con.executescript(OLD_SCHEMA)
    con.executemany(
        "INSERT INTO users (id, username, password_hash, role, created_at) VALUES (?,?,?,?,?)",
        [
            (1, "boss", hash_password("boss-password-123"), "admin", "2026-01-02 03:04:05"),
            (2, "op", hash_password("op-password-12345"), "operator", "2026-01-02 03:04:05"),
            (3, "view", hash_password("view-password-123"), "viewer", "2026-01-02 03:04:05"),
        ],
    )
    for statement in [*OLD_ROWS, *extra]:
        con.execute(statement)
    con.commit()
    con.close()
    return path


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _all(model) -> list:
    db = get_sessionmaker()()
    try:
        return db.execute(select(model)).scalars().all()
    finally:
        db.close()


def test_import_backfills_the_default_project_and_copies_everything(empty) -> None:
    source = _legacy_db(empty)
    before = _digest(source)

    counts = import_sqlite(source, log=lambda _: None)

    assert _digest(source) == before  # the original is never written
    assert counts["users"] == 3 and counts["runs"] == 1 and counts["audit_events"] == 1
    projects = _all(Project)
    assert [p.name for p in projects] == ["Default"]
    default_id = projects[0].id
    for model in (Playbook, Run):
        assert {row.project_id for row in _all(model)} == {default_id}
    members = sorted((m.user_id, m.role) for m in _all(ProjectMember))
    assert members == [(2, "operator"), (3, "viewer")]  # the global admin needs none
    assert _all(AuditEvent)[0].project_id is None
    boss = next(u for u in _all(User) if u.username == "boss")
    assert boss.created_at == datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)  # stored UTC, kept


def test_imported_users_keep_working_access_and_ids_continue(empty) -> None:
    import_sqlite(_legacy_db(empty), log=lambda _: None)

    op = TestClient(app)
    login = op.post("/api/auth/login", json={"username": "op", "password": "op-password-12345"})
    assert login.status_code == 200
    assert [p["name"] for p in op.get("/api/auth/me").json()["projects"]] == ["Default"]
    assert [p["name"] for p in op.get("/api/playbooks").json()] == ["old-playbook"]
    assert op.get("/api/users").status_code == 403

    boss = TestClient(app)
    boss.post("/api/auth/login", json={"username": "boss", "password": "boss-password-123"})
    assert [r["id"] for r in boss.get("/api/runs").json()] == [1]
    created = boss.post("/api/playbooks", json={"name": "new.yml", "content": "- hosts: all\n"})
    assert created.status_code == 201 and created.json()["id"] == 2  # sequences were moved on


def test_a_pre_rbac_database_keeps_its_sole_user_as_admin(empty) -> None:
    path = empty / "ansideck.db"
    con = sqlite3.connect(path)
    con.executescript(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username VARCHAR(150) UNIQUE,"
        " password_hash VARCHAR(255), created_at DATETIME DEFAULT CURRENT_TIMESTAMP);"
    )
    con.execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        ("legacy", hash_password("legacy-password-123")),
    )
    con.commit()
    con.close()

    import_sqlite(path, log=lambda _: None)

    [user] = _all(User)
    assert (user.username, user.role, user.is_active, user.session_version) == (
        "legacy",
        "admin",
        True,
        0,
    )
    legacy = TestClient(app)
    response = legacy.post(
        "/api/auth/login", json={"username": "legacy", "password": "legacy-password-123"}
    )
    assert response.status_code == 200 and response.json()["role"] == "admin"


def test_check_runs_everything_and_writes_nothing(empty) -> None:
    counts = import_sqlite(_legacy_db(empty), check=True, log=lambda _: None)
    assert counts["users"] == 3
    assert _all(User) == [] and _all(Project) == []


def test_it_only_imports_into_an_empty_database(empty) -> None:
    source = _legacy_db(empty)
    db = get_sessionmaker()()
    seed_fresh_install(db)
    db.close()
    with pytest.raises(ImportFailed, match="already has data"):
        import_sqlite(source, log=lambda _: None)
    assert [u.username for u in _all(User)] == ["admin"]


def test_orphaned_set_null_references_are_cleared_and_reported(empty) -> None:
    source = _legacy_db(
        empty,
        [
            "INSERT INTO runs (id, playbook_id, playbook_name, inventory_id, inventory_name,"
            " credential_id, credential_name, become, status, triggered_by)"
            " VALUES (2, 99, 'gone', 1, 'old-inv', 1, 'old-cred', 0, 'failed', 'boss')"
        ],
    )
    logged: list[str] = []
    import_sqlite(source, log=logged.append)
    run = next(r for r in _all(Run) if r.id == 2)
    assert run.playbook_id is None and run.playbook_name == "gone"
    assert logged == [
        "fixed: runs row 2: playbook_id=99 pointed at a missing playbooks row; set to NULL"
    ]


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        (
            ["UPDATE users SET username = '" + "u" * 151 + "' WHERE id = 3"],
            "users row 3: username is 151 characters, the limit is 150",
        ),
        (
            [
                "CREATE TABLE inventory_hosts (id INTEGER PRIMARY KEY, inventory_id INTEGER,"
                " hostname VARCHAR(255), vars JSON)",
                "INSERT INTO inventory_hosts VALUES (1, 1, 'web', 'not json')",
            ],
            "inventory_hosts: a value can't be read",
        ),
    ],
    ids=["too-long", "bad-json"],
)
def test_bad_rows_stop_the_import_and_name_the_row(empty, extra, message) -> None:
    with pytest.raises(ImportFailed, match=message):
        import_sqlite(_legacy_db(empty, extra), log=lambda _: None)
    assert _all(User) == []  # all or nothing


def test_it_refuses_files_that_are_not_ansideck_databases(empty) -> None:
    with pytest.raises(ImportFailed, match="does not exist"):
        import_sqlite(empty / "missing.db")
    (empty / "text.db").write_text("hello")
    with pytest.raises(ImportFailed, match="not a readable SQLite database"):
        import_sqlite(empty / "text.db")
    sqlite3.connect(empty / "other.db").executescript("CREATE TABLE t (x);")
    with pytest.raises(ImportFailed, match="not an AnsiDeck database"):
        import_sqlite(empty / "other.db")


def test_the_cli_reports_counts_and_failures(empty, capsys) -> None:
    source = _legacy_db(empty)
    assert cli.main(["import-sqlite", str(source), "--check"]) == 0
    assert "Nothing was written" in capsys.readouterr().out
    assert cli.main(["import-sqlite", str(source)]) == 0
    out = capsys.readouterr().out
    assert "users" in out and "was not changed" in out
    assert cli.main(["import-sqlite", str(source)]) == 1
    assert "already has data" in capsys.readouterr().err
    assert cli.main(["migrate"]) == 0


def test_startup_refuses_an_empty_database_next_to_old_data(empty) -> None:
    _legacy_db(empty)
    db = get_sessionmaker()()
    try:
        with pytest.raises(PendingSqliteImport, match="import-sqlite"):
            refuse_to_start_over_legacy_data(db)
        with pytest.raises(PendingSqliteImport), TestClient(app):  # the real lifespan
            pass
        assert _all(User) == []  # no admin was seeded over it
        import_sqlite(empty / "ansideck.db", log=lambda _: None)
        refuse_to_start_over_legacy_data(db)  # data is in: the old file no longer matters
    finally:
        db.close()


def test_a_deleted_default_project_is_not_recreated(client: TestClient) -> None:
    with get_engine().begin() as conn:
        conn.execute(text("DELETE FROM projects"))
    db = get_sessionmaker()()
    seed_fresh_install(db)  # every later startup
    db.close()
    assert _all(Project) == []
