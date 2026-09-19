from fastapi import Cookie, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import User
from app.security import verify_session_token

SESSION_COOKIE_NAME = "ansideck_session"


def authenticate_token(db: Session, token: str | None) -> User | None:
    """Resolves a session token to an active user, re-reading the DB every time so
    deactivation, role changes and password changes take effect immediately."""
    if not token:
        return None
    parsed = verify_session_token(token)
    if parsed is None:
        return None
    user_id, session_version = parsed
    user = db.get(User, user_id)
    if user is None or not user.is_active or user.session_version != session_version:
        return None
    return user


def get_current_user(
    ansideck_session: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME),
    db: Session = Depends(get_db),
) -> User:
    if not ansideck_session:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    user = authenticate_token(db, ansideck_session)
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session invalid or expired")
    return user
