"""Alembic environment: the URL comes from the app settings and the target schema from
the SQLAlchemy models. init_db() passes in an open connection (holding the migration lock);
the `alembic` CLI connects on its own."""

from alembic import context
from sqlalchemy import create_engine, pool

import app.models  # noqa: F401  (registers every table on Base.metadata)
from app.config import get_settings
from app.db import Base

target_metadata = Base.metadata


def _run(connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    raise SystemExit("Offline (--sql) migrations are not supported; run against a database.")

connection = context.config.attributes.get("connection")
if connection is not None:
    _run(connection)
else:
    engine = create_engine(get_settings().database_url, poolclass=pool.NullPool)
    with engine.connect() as connection:
        _run(connection)
        connection.commit()
