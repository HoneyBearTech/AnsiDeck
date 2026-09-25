from pathlib import Path

from sqlalchemy.orm import Session

from app.config import get_settings
from app.crypto import hash_password
from app.db import DEFAULT_PROJECT_NAME
from app.models import Project, User

LEGACY_SQLITE_NAME = "ansideck.db"


class PendingSqliteImport(RuntimeError):
    """Postgres is empty but the data directory still holds a pre-Postgres SQLite DB."""


def refuse_to_start_over_legacy_data(db: Session) -> None:
    """Seeding a fresh admin next to an old SQLite database would bury that data (the
    import refuses a non-empty target), so stop and say how to bring it over instead."""
    legacy = Path(get_settings().data_dir) / LEGACY_SQLITE_NAME
    if legacy.exists() and db.query(User.id).first() is None:
        raise PendingSqliteImport(
            f"{legacy} holds data from before the move to Postgres, and the Postgres database "
            "is empty. Import it once with:\n"
            f"  python -m app.cli import-sqlite {legacy}\n"
            "(in the dev compose stack: docker compose run --rm backend uv run python -m "
            f"app.cli import-sqlite {legacy}). To start fresh instead, move the file away."
        )


def seed_fresh_install(db: Session) -> None:
    """Idempotent: on a brand-new install (no users yet) creates the Default project and
    the admin from ADMIN_USERNAME/ADMIN_PASSWORD. No-op on every later startup, so a
    deliberately deleted Default project never comes back."""
    if db.query(User).count() > 0:
        return
    if db.query(Project.id).first() is None:
        db.add(Project(name=DEFAULT_PROJECT_NAME, description="Created automatically"))
    settings = get_settings()
    db.add(
        User(
            username=settings.admin_username,
            password_hash=hash_password(settings.admin_password),
            role="admin",
        )
    )
    db.commit()
