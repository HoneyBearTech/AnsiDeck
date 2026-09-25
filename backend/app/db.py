from collections.abc import Generator
from functools import lru_cache
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import MetaData, create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings

DEFAULT_PROJECT_NAME = "Default"
ALEMBIC_INI = Path(__file__).resolve().parent.parent / "alembic.ini"

# Deterministic constraint/index names, so Alembic migrations can refer to them.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

# Held for the duration of a schema upgrade, so several processes (API, workers) starting
# at once apply migrations one at a time. Any fixed 64-bit number works.
_MIGRATION_LOCK_KEY = 0x616E_7369_6465_636B  # "ansideck"


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


@lru_cache
def get_engine() -> Engine:
    # Run threads and request handlers share the pool; pre-ping survives a DB restart.
    return create_engine(
        get_settings().database_url, pool_pre_ping=True, pool_size=10, max_overflow=20
    )


@lru_cache
def get_sessionmaker() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), autoflush=False, autocommit=False)


def get_db() -> Generator[Session, None, None]:
    session = get_sessionmaker()()
    try:
        yield session
    finally:
        session.close()


def alembic_config() -> Config:
    return Config(str(ALEMBIC_INI))


def init_db() -> None:
    """Brings the schema to the latest Alembic revision (a no-op when it already is)."""
    with get_engine().begin() as connection:
        connection.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": _MIGRATION_LOCK_KEY})
        config = alembic_config()
        config.attributes["connection"] = connection
        command.upgrade(config, "head")
