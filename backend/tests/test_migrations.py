from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory

from app.db import Base, alembic_config, get_engine


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
