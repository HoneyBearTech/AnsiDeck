from collections.abc import Generator
from functools import lru_cache
from pathlib import Path

from sqlalchemy import create_engine, event, inspect
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings

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


class Base(DeclarativeBase):
    pass


@lru_cache
def get_engine() -> Engine:
    settings = get_settings()
    data_dir = Path(settings.data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    engine = create_engine(
        f"sqlite:///{data_dir / 'ansideck.db'}",
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    return engine


@lru_cache
def get_sessionmaker() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), autoflush=False, autocommit=False)


def get_db() -> Generator[Session, None, None]:
    session = get_sessionmaker()()
    try:
        yield session
    finally:
        session.close()


def _ensure_run_columns(engine: Engine) -> None:
    inspector = inspect(engine)
    if not inspector.has_table("runs"):
        return  # fresh DB — create_all() below creates it with every column
    existing = {col["name"] for col in inspector.get_columns("runs")}
    with engine.begin() as conn:
        for column, ddl in _RUN_COLUMN_MIGRATIONS.items():
            if column not in existing:
                conn.exec_driver_sql(ddl)


def init_db() -> None:
    engine = get_engine()
    # Create any missing tables (e.g. a brand-new vault_passwords table on an
    # upgrading instance) before patching columns on existing ones, so a new
    # FK column (like Run.vault_password_id) always has its target table
    # present by the time it's added.
    Base.metadata.create_all(bind=engine)
    _ensure_run_columns(engine)
