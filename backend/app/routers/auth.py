from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from app.config import get_settings
from app.crypto import hash_password, verify_password
from app.db import get_db
from app.dependencies import SESSION_COOKIE_NAME, get_current_user
from app.models import User
from app.schemas.auth import ChangePasswordRequest, LoginRequest, UserOut
from app.security import SESSION_MAX_AGE_SECONDS, create_session_token

router = APIRouter()


@router.post("/login", response_model=UserOut)
def login(payload: LoginRequest, response: Response, db: Session = Depends(get_db)) -> UserOut:
    user = db.query(User).filter(User.username == payload.username).first()
    if user is None or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password")

    settings = get_settings()
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=create_session_token(user.username),
        httponly=True,
        samesite="lax",
        secure=settings.cookie_secure,
        max_age=SESSION_MAX_AGE_SECONDS,
        path="/",
    )
    return UserOut(username=user.username)


@router.post("/logout")
def logout(response: Response) -> dict[str, bool]:
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return {"ok": True}


@router.get("/me", response_model=UserOut)
def me(current_user: str = Depends(get_current_user)) -> UserOut:
    return UserOut(username=current_user)


@router.post("/change-password")
def change_password(
    payload: ChangePasswordRequest,
    current_user: str = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, bool]:
    user = db.query(User).filter(User.username == current_user).first()
    if user is None or not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Current password is incorrect")
    user.password_hash = hash_password(payload.new_password)
    db.commit()
    return {"ok": True}
