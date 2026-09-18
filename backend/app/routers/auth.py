from fastapi import APIRouter, Depends, HTTPException, Response, status

from app.config import get_settings
from app.dependencies import SESSION_COOKIE_NAME, get_current_user
from app.schemas.auth import LoginRequest, UserOut
from app.security import SESSION_MAX_AGE_SECONDS, create_session_token

router = APIRouter()


@router.post("/login", response_model=UserOut)
def login(payload: LoginRequest, response: Response) -> UserOut:
    settings = get_settings()
    if payload.username != settings.admin_username or payload.password != settings.admin_password:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password")

    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=create_session_token(payload.username),
        httponly=True,
        samesite="lax",
        secure=settings.cookie_secure,
        max_age=SESSION_MAX_AGE_SECONDS,
        path="/",
    )
    return UserOut(username=payload.username)


@router.post("/logout")
def logout(response: Response) -> dict[str, bool]:
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return {"ok": True}


@router.get("/me", response_model=UserOut)
def me(current_user: str = Depends(get_current_user)) -> UserOut:
    return UserOut(username=current_user)
