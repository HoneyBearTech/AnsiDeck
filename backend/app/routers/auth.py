from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app import audit
from app.config import get_settings
from app.crypto import hash_password, verify_password
from app.db import get_db
from app.dependencies import SESSION_COOKIE_NAME, authenticate_token
from app.hardening import client_ip, ip_login_throttle, user_login_throttle
from app.models import Project, User
from app.permissions import (
    effective_permissions,
    is_global_admin,
    project_role_permissions,
    require_authenticated,
    user_project_roles,
)
from app.schemas.auth import ChangePasswordRequest, LoginRequest, ProjectAccess, UserOut
from app.security import SESSION_MAX_AGE_SECONDS, create_session_token

router = APIRouter()

_authenticated = require_authenticated()

# Verified against when the username doesn't exist, so an unknown user costs the
# same argon2 time as a wrong password (no timing/enumeration oracle).
_dummy_hash: str | None = None


def _get_dummy_hash() -> str:
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = hash_password("ansideck-dummy-password")
    return _dummy_hash


def _to_out(db: Session, user: User) -> UserOut:
    if is_global_admin(user):
        access = {project.id: (project, "admin") for project in db.query(Project).all()}
    else:
        roles = user_project_roles(db, user)
        projects = db.query(Project).filter(Project.id.in_(roles.keys())).all() if roles else []
        access = {project.id: (project, roles[project.id]) for project in projects}
    return UserOut(
        username=user.username,
        role=user.role,
        permissions=sorted(p.value for p in effective_permissions(db, user)),
        projects=[
            ProjectAccess(
                id=project.id,
                name=project.name,
                role=role,
                permissions=sorted(p.value for p in project_role_permissions(role)),
            )
            for project, role in sorted(access.values(), key=lambda pr: pr[0].name.lower())
        ],
    )


def _set_session_cookie(response: Response, user: User) -> None:
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=create_session_token(user.id, user.session_version),
        httponly=True,
        samesite="lax",
        secure=get_settings().cookie_secure,
        max_age=SESSION_MAX_AGE_SECONDS,
        path="/",
    )


@router.post("/login", response_model=UserOut)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> UserOut:
    ip = client_ip(request)
    user_key = (ip, payload.username.lower()[:150])
    if user_login_throttle.blocked(user_key) or ip_login_throttle.blocked(ip):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Too many failed login attempts. Try again in a few minutes.",
            headers={"Retry-After": "300"},
        )

    user = db.query(User).filter(User.username == payload.username).first()
    password_ok = verify_password(
        payload.password, user.password_hash if user else _get_dummy_hash()
    )
    if user is None or not password_ok or not user.is_active:
        user_login_throttle.record_failure(user_key)
        ip_login_throttle.record_failure(ip)
        # Only real usernames are recorded verbatim, so attackers can't fill the
        # audit table with arbitrary strings; writes are bounded by the IP throttle.
        audit.record(
            db,
            "auth.login",
            outcome="failure",
            actor_username=user.username if user else "(unknown user)",
            ip=ip,
            detail={"reason": "inactive" if user and password_ok else "bad credentials"},
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password")

    user_login_throttle.reset(user_key)
    _set_session_cookie(response, user)
    audit.record(db, "auth.login", actor=user, ip=ip)
    return _to_out(db, user)


@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    ansideck_session: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME),
    db: Session = Depends(get_db),
) -> dict[str, bool]:
    user = authenticate_token(db, ansideck_session)
    if user is not None:
        audit.record(db, "auth.logout", actor=user, ip=client_ip(request))
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return {"ok": True}


@router.get("/me", response_model=UserOut)
def me(current_user: User = Depends(_authenticated), db: Session = Depends(get_db)) -> UserOut:
    return _to_out(db, current_user)


@router.post("/change-password")
def change_password(
    payload: ChangePasswordRequest,
    request: Request,
    response: Response,
    current_user: User = Depends(_authenticated),
    db: Session = Depends(get_db),
) -> dict[str, bool]:
    # Guesses here share the login throttle: a stolen session must not become an
    # unthrottled way to find the password (and keep the account for good).
    ip = client_ip(request)
    user_key = (ip, current_user.username.lower()[:150])
    if user_login_throttle.blocked(user_key) or ip_login_throttle.blocked(ip):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Too many failed password attempts. Try again in a few minutes.",
            headers={"Retry-After": "300"},
        )
    if not verify_password(payload.current_password, current_user.password_hash):
        user_login_throttle.record_failure(user_key)
        ip_login_throttle.record_failure(ip)
        audit.record(
            db,
            "auth.password_change",
            outcome="failure",
            actor=current_user,
            ip=ip,
            detail={"reason": "wrong current password"},
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Current password is incorrect")
    user_login_throttle.reset(user_key)
    if payload.new_password.lower() == current_user.username.lower():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Password must not equal your username")
    current_user.password_hash = hash_password(payload.new_password)
    current_user.session_version += 1  # signs out every other session
    db.commit()
    _set_session_cookie(response, current_user)  # ...but keep this one
    audit.record(db, "auth.password_change", actor=current_user, ip=ip)
    return {"ok": True}
