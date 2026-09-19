from sqlalchemy.orm import Session

from app.config import get_settings
from app.crypto import hash_password
from app.models import User


def seed_admin_user(db: Session) -> None:
    """Idempotent: seeds one admin user from ADMIN_USERNAME/ADMIN_PASSWORD only if
    the users table is empty. No-op on every subsequent startup."""
    if db.query(User).count() > 0:
        return
    settings = get_settings()
    db.add(
        User(
            username=settings.admin_username,
            password_hash=hash_password(settings.admin_password),
            role="admin",
        )
    )
    db.commit()
