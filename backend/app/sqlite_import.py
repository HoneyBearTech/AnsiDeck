"""One-way import of a pre-Postgres SQLite database (`python -m app.cli import-sqlite`).

The source file is never written: it is copied with SQLite's backup API, the copy is
brought to the last SQLite schema with the migrations AnsiDeck used before Alembic (kept
here verbatim, their only remaining use), and then every table is copied into an *empty*
Postgres database in one transaction, so an import either fully succeeds or leaves
Postgres untouched.
"""

import sqlite3
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import (
    JSON,
    DateTime,
    Engine,
    Integer,
    String,
    create_engine,
    func,
    insert,
    inspect,
    select,
    text,
)
from sqlalchemy.sql.schema import Table

import app.models  # noqa: F401  (registers every table on Base.metadata)
from app.db import DEFAULT_PROJECT_NAME, Base, get_engine, init_db


class ImportFailed(Exception):
    """The import stopped; Postgres was left unchanged."""


class _CheckOnly(Exception):
    pass


# --- the SQLite schema history (verbatim from app/db.py before Phase 4A) ------------------

# Columns added to existing tables after their first release. create_all()
# only creates missing *tables*, not missing *columns* on ones that already
# exist — without this, a real (non-test) instance upgrading past the pass
# that added these would silently never get them. Explicit and manual
# rather than a generic migration engine — fine while it's one table and a
# handful of columns; revisit (Alembic) if this list keeps growing.
_RUN_COLUMN_MIGRATIONS = {
    "check_mode": "ALTER TABLE runs ADD COLUMN check_mode BOOLEAN DEFAULT 0",
    "diff_mode": "ALTER TABLE runs ADD COLUMN diff_mode BOOLEAN DEFAULT 0",
    "limit": 'ALTER TABLE runs ADD COLUMN "limit" VARCHAR(500)',
    "extra_vars": "ALTER TABLE runs ADD COLUMN extra_vars JSON",
    "vault_password_id": (
        "ALTER TABLE runs ADD COLUMN vault_password_id INTEGER "
        "REFERENCES vault_passwords(id) ON DELETE SET NULL"
    ),
    "vault_password_name": "ALTER TABLE runs ADD COLUMN vault_password_name VARCHAR(150)",
}

# Same idea for the users table. The role column defaults to 'admin' *for the
# ALTER only*, so the pre-RBAC single user becomes an admin instead of being
# locked out; new rows always get an explicit role from the ORM.
_USER_COLUMN_MIGRATIONS = {
    "role": "ALTER TABLE users ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'admin'",
    "is_active": "ALTER TABLE users ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT 1",
    "session_version": "ALTER TABLE users ADD COLUMN session_version INTEGER NOT NULL DEFAULT 0",
    "created_by": "ALTER TABLE users ADD COLUMN created_by VARCHAR(150)",
    "email": "ALTER TABLE users ADD COLUMN email VARCHAR(320)",
    "sso_issuer": "ALTER TABLE users ADD COLUMN sso_issuer VARCHAR(500)",
    "sso_subject": "ALTER TABLE users ADD COLUMN sso_subject VARCHAR(255)",
    "totp_secret": "ALTER TABLE users ADD COLUMN totp_secret BLOB",
    "totp_pending_secret": "ALTER TABLE users ADD COLUMN totp_pending_secret BLOB",
    "totp_last_counter": "ALTER TABLE users ADD COLUMN totp_last_counter INTEGER",
    "totp_recovery_hashes": "ALTER TABLE users ADD COLUMN totp_recovery_hashes JSON",
}

# create_all() only creates indexes together with a brand-new table, so upgraded
# databases get the SSO ones here (same names as in models.py).
_USER_INDEXES = (
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_users_email_lower ON users (lower(email))",
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_users_sso_identity ON users (sso_issuer, sso_subject)",
)

# project_id is added nullable: SQLite refuses ADD COLUMN ... REFERENCES with any
# default, so rows are backfilled to the Default project by _backfill_projects().
# Fresh databases get the column NOT NULL from the models.
_PROJECT_SCOPED_TABLES = ("playbooks", "inventories", "credentials", "vault_passwords", "runs")
_PROJECT_COLUMN_MIGRATION = (
    "ALTER TABLE {table} ADD COLUMN project_id INTEGER REFERENCES projects(id)"
)
_AUDIT_PROJECT_COLUMN_MIGRATION = "ALTER TABLE audit_events ADD COLUMN project_id INTEGER"
_SCHEMA_VERSION = 1  # PRAGMA user_version: 1 = projects introduced and backfilled


def _ensure_columns(engine: Engine, table: str, migrations: dict[str, str]) -> None:
    inspector = inspect(engine)
    if not inspector.has_table(table):
        return  # fresh DB — create_all() creates it with every column
    existing = {col["name"] for col in inspector.get_columns(table)}
    with engine.begin() as conn:
        for column, ddl in migrations.items():
            if column not in existing:
                conn.exec_driver_sql(ddl)


def _backfill_projects(engine: Engine) -> None:
    """One-time upgrade: create the Default project, assign every pre-existing row
    to it, and give each existing non-admin user membership with their current
    role so nobody loses access. Guarded by PRAGMA user_version so it never
    resurrects Default after an admin deliberately deletes projects."""
    with engine.begin() as conn:
        if (conn.exec_driver_sql("PRAGMA user_version").scalar() or 0) >= _SCHEMA_VERSION:
            return
        row = conn.exec_driver_sql(
            "SELECT id FROM projects WHERE name = ?", (DEFAULT_PROJECT_NAME,)
        ).first()
        if row is None:
            conn.exec_driver_sql(
                "INSERT INTO projects (name, description) VALUES (?, ?)",
                (DEFAULT_PROJECT_NAME, "Created automatically for existing data"),
            )
            row = conn.exec_driver_sql(
                "SELECT id FROM projects WHERE name = ?", (DEFAULT_PROJECT_NAME,)
            ).first()
        default_id = row[0]
        for table in _PROJECT_SCOPED_TABLES:
            conn.exec_driver_sql(
                f"UPDATE {table} SET project_id = ? WHERE project_id IS NULL", (default_id,)
            )
        conn.exec_driver_sql(
            "INSERT OR IGNORE INTO project_members (project_id, user_id, role) "
            "SELECT ?, id, role FROM users WHERE role != 'admin'",
            (default_id,),
        )
        conn.exec_driver_sql(f"PRAGMA user_version = {_SCHEMA_VERSION}")


def upgrade_legacy_sqlite(engine: Engine) -> None:
    """What init_db() did on SQLite: bring any older AnsiDeck database to the last SQLite
    schema (missing tables and columns, SSO indexes, the Default-project backfill)."""
    Base.metadata.create_all(bind=engine)
    _ensure_columns(engine, "runs", _RUN_COLUMN_MIGRATIONS)
    _ensure_columns(engine, "users", _USER_COLUMN_MIGRATIONS)
    with engine.begin() as conn:
        for ddl in _USER_INDEXES:
            conn.exec_driver_sql(ddl)
    for table in _PROJECT_SCOPED_TABLES:
        _ensure_columns(
            engine, table, {"project_id": _PROJECT_COLUMN_MIGRATION.format(table=table)}
        )
    _ensure_columns(engine, "audit_events", {"project_id": _AUDIT_PROJECT_COLUMN_MIGRATION})
    _backfill_projects(engine)


# --- the copy ----------------------------------------------------------------------------


def _fill_missing(table: Table, row: dict, now: datetime) -> list[str]:
    """SQLite let older rows keep NULL in columns that are NOT NULL today (e.g. timestamps
    added later). Fills what has an obvious value; returns the columns it still can't fill."""
    unfillable = []
    for column in table.columns:
        if row.get(column.name) is not None or column.nullable or column.primary_key:
            continue
        default = column.default
        if isinstance(column.type, DateTime):
            row[column.name] = row.get("created_at") or now
        elif default is not None and default.is_scalar:
            row[column.name] = default.arg
        elif isinstance(column.type, JSON):
            row[column.name] = {}
        else:
            unfillable.append(column.name)
    return unfillable


def _problems(table: Table, row: dict, known_ids: dict[str, set], fixes: list[str]) -> list[str]:
    where = f"{table.name} row {row.get('id', row)}"
    found = []
    for column in table.columns:
        value = row.get(column.name)
        if isinstance(value, datetime) and value.tzinfo is None:
            row[column.name] = value.replace(tzinfo=UTC)  # the app always stored UTC
        if isinstance(column.type, String) and column.type.length and isinstance(value, str):
            if len(value) > column.type.length:
                found.append(
                    f"{where}: {column.name} is {len(value)} characters, "
                    f"the limit is {column.type.length}"
                )
        for fk in column.foreign_keys:
            target = fk.column.table.name
            if value is None or value in known_ids.get(target, set()):
                continue
            if fk.ondelete and fk.ondelete.upper() == "SET NULL":
                row[column.name] = None  # what the database would have done on delete
                fixes.append(
                    f"{where}: {column.name}={value} pointed at a missing {target} row; set to NULL"
                )
            else:
                found.append(f"{where}: {column.name}={value} points at a missing {target} row")
    return found


def _read_rows(source: Engine, table: Table) -> list[dict]:
    try:
        with source.connect() as conn:
            return [dict(r._mapping) for r in conn.execute(select(table))]
    except ValueError as exc:  # e.g. a JSON column holding text that isn't JSON
        raise ImportFailed(f"{table.name}: a value can't be read ({exc})") from exc


def _copy(
    source: Engine, target: Engine, check: bool, log: Callable[[str], None]
) -> dict[str, int]:
    tables = Base.metadata.sorted_tables  # parents before children
    now = datetime.now(UTC)
    counts: dict[str, int] = {}
    fixes: list[str] = []
    try:
        with target.begin() as dst:
            non_empty = [
                t.name for t in tables if dst.execute(select(func.count()).select_from(t)).scalar()
            ]
            if non_empty:
                raise ImportFailed(
                    "The Postgres database already has data (in "
                    + ", ".join(non_empty)
                    + "). The import only goes into an empty database."
                )
            known_ids: dict[str, set] = {}
            for table in tables:
                rows = _read_rows(source, table)
                problems = []
                for row in rows:
                    missing = _fill_missing(table, row, now)
                    problems += [f"{table.name} row {row.get('id')}: {c} is empty" for c in missing]
                    problems += _problems(table, row, known_ids, fixes)
                if problems:
                    raise ImportFailed(
                        "\n".join(problems[:20])
                        + (f"\n... and {len(problems) - 20} more" if len(problems) > 20 else "")
                    )
                if rows:
                    dst.execute(insert(table), rows)
                if "id" in table.c:
                    known_ids[table.name] = {row["id"] for row in rows}
                counts[table.name] = len(rows)

            for table in tables:
                id_column = table.c.get("id")
                if (
                    id_column is not None
                    and id_column.primary_key
                    and isinstance(id_column.type, Integer)
                ):
                    dst.execute(
                        text(
                            f"SELECT setval(pg_get_serial_sequence(:t, 'id'), "
                            f'COALESCE(MAX(id), 1), MAX(id) IS NOT NULL) FROM "{table.name}"'
                        ),
                        {"t": table.name},
                    )
                copied = dst.execute(select(func.count()).select_from(table)).scalar()
                if copied != counts[table.name]:
                    raise ImportFailed(
                        f"{table.name}: read {counts[table.name]} rows but {copied} arrived"
                    )
            for fix in fixes:
                log(f"fixed: {fix}")
            if check:
                raise _CheckOnly
    except _CheckOnly:
        pass
    return counts


def import_sqlite(
    path: Path, *, check: bool = False, log: Callable[[str], None] = print
) -> dict[str, int]:
    """Copies an AnsiDeck SQLite database into the (empty) Postgres database. With
    check=True everything runs and is then rolled back. Returns rows per table."""
    if not path.is_file():
        raise ImportFailed(f"{path} does not exist")
    init_db()  # the target schema at the latest revision
    with tempfile.TemporaryDirectory() as tmp:
        copy = Path(tmp) / "legacy.db"
        try:
            original = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
            try:
                with sqlite3.connect(copy) as duplicate:
                    original.backup(duplicate)
            finally:
                original.close()
        except sqlite3.DatabaseError as exc:
            raise ImportFailed(f"{path} is not a readable SQLite database ({exc})") from exc
        source = create_engine(f"sqlite:///{copy}")
        try:
            if not inspect(source).has_table("users"):
                raise ImportFailed(f"{path} is not an AnsiDeck database (no users table)")
            upgrade_legacy_sqlite(source)
            return _copy(source, get_engine(), check, log)
        finally:
            source.dispose()
