from fastapi import Cookie, HTTPException, status

from app.security import verify_session_token

SESSION_COOKIE_NAME = "ansideck_session"


def get_current_user(
    ansideck_session: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME),
) -> str:
    if not ansideck_session:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    username = verify_session_token(ansideck_session)
    if not username:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session invalid or expired")
    return username
