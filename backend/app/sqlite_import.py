"""One-way import of a pre-Postgres SQLite database (`python -m app.cli import-sqlite`).

The source file is never written: it is copied with SQLite's backup API, the copy is
brought to the last SQLite schema with the migrations AnsiDeck used before Alembic (kept
here verbatim, their only remaining use), and then every table is copied into an *empty*
Postgres database in one transaction, so an import either fully succeeds or leaves
Postgres untouched.

The copy lands in the schema SQLite last had (Alembic revision SQLITE_ERA_REVISION), and
the later migrations then run on the imported rows in the same transaction, so their
backfills apply exactly as they did on installs that were already on Postgres.
"""

import sqlite3
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from psycopg.errors import LockNotAvailable
from sqlalchemy import (
    JSON,
    Column,
    Connection,
    DateTime,
    Engine,
    Integer,
    MetaData,
    String,
    create_engine,
    func,
    insert,
    inspect,
    select,
    text,
)
from sqlalchemy.exc import OperationalError
from sqlalchemy.sql.schema import Table

import app.models  # noqa: F401  (registers every table on Base.metadata)
from app.db import DEFAULT_PROJECT_NAME, Base, get_engine, upgrade_schema

# The Alembic revision whose schema matches the last SQLite one (the Postgres baseline).
SQLITE_ERA_REVISION = "0001"
# The import rebuilds the (empty) schema, which waits for every other open transaction on
# those tables; with the backend still running that would never end, so give up instead.
LOCK_TIMEOUT = "10s"


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
        # Reflected tables carry no Python-side defaults; the model's still apply.
        model_column = _model_column(table.name, column.name)
        default = model_column.default if model_column is not None else None
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


def _model_column(table: str, column: str) -> Column | None:
    model = Base.metadata.tables.get(table)
    return model.c.get(column) if model is not None else None


def _read_rows(source: Engine, table: Table) -> list[dict]:
    """The source rows for a target table. The legacy upgrade gave the SQLite copy every
    column of the SQLite-era schema; read them with the model's types, which know how
    SQLite stored JSON, booleans and timestamps."""
    columns = []
    for column in table.columns:
        model_column = _model_column(table.name, column.name)
        typed_by = model_column if model_column is not None else column
        columns.append(Column(column.name, typed_by.type))
    try:
        with source.connect() as conn:
            query = select(Table(table.name, MetaData(), *columns))
            return [dict(r._mapping) for r in conn.execute(query)]
    except ValueError as exc:  # e.g. a JSON column holding text that isn't JSON
        raise ImportFailed(f"{table.name}: a value can't be read ({exc})") from exc


def _reset_to_sqlite_era_schema(dst: Connection) -> list[Table]:
    """Refuses a target that holds data; otherwise rebuilds it at SQLITE_ERA_REVISION
    (it is empty, so nothing is lost) and returns its tables, parents first."""
    # Only AnsiDeck's own tables: the database may be shared with something else.
    ours = {*Base.metadata.tables, "alembic_version"}
    existing = MetaData()
    existing.reflect(dst, only=lambda name, _: name in ours)
    non_empty = [
        t.name
        for t in existing.sorted_tables
        if t.name != "alembic_version" and dst.execute(select(func.count()).select_from(t)).scalar()
    ]
    if non_empty:
        raise ImportFailed(
            "The Postgres database already has data (in "
            + ", ".join(non_empty)
            + "). The import only goes into an empty database."
        )
    existing.drop_all(dst)
    upgrade_schema(dst, SQLITE_ERA_REVISION)
    target = MetaData()
    target.reflect(dst, only=lambda name, _: name in ours)
    return [t for t in target.sorted_tables if t.name != "alembic_version"]


def _copy(
    source: Engine, target: Engine, check: bool, log: Callable[[str], None]
) -> dict[str, int]:
    now = datetime.now(UTC)
    counts: dict[str, int] = {}
    fixes: list[str] = []
    try:
        with target.begin() as dst:
            dst.execute(text(f"SET LOCAL lock_timeout = '{LOCK_TIMEOUT}'"))
            tables = _reset_to_sqlite_era_schema(dst)
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
            upgrade_schema(dst)  # the later migrations, on the imported rows
            for fix in fixes:
                log(f"fixed: {fix}")
            if check:
                raise _CheckOnly
    except _CheckOnly:
        pass
    except OperationalError as exc:
        if not isinstance(exc.orig, LockNotAvailable):
            raise
        raise ImportFailed(
            "The database is in use (another connection holds its tables). Stop the backend "
            "and anything else connected to it, then run the import again."
        ) from exc
    return counts


def import_sqlite(
    path: Path, *, check: bool = False, log: Callable[[str], None] = print
) -> dict[str, int]:
    """Copies an AnsiDeck SQLite database into the (empty) Postgres database. With
    check=True everything runs and is then rolled back. Returns rows per table."""
    if not path.is_file():
        raise ImportFailed(f"{path} does not exist")
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
