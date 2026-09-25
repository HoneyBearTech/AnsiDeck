from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app import audit, totp
from app.config import get_settings
from app.crypto import hash_password, verify_password
from app.db import get_db
from app.dependencies import SESSION_COOKIE_NAME, authenticate_token
from app.hardening import client_ip, ip_login_throttle, totp_user_throttle, user_login_throttle
from app.models import Project, User
from app.permissions import (
    effective_permissions,
    is_global_admin,
    project_role_permissions,
    require_authenticated,
    user_project_roles,
)
from app.schemas.auth import (
    ChangePasswordRequest,
    LoginRequest,
    MfaChallenge,
    MfaLoginRequest,
    PasswordConfirmRequest,
    ProjectAccess,
    RecoveryCodesOut,
    TotpCodeRequest,
    TotpDisableRequest,
    TotpSetupOut,
    UserOut,
)
from app.security import (
    MFA_MAX_AGE_SECONDS,
    SESSION_MAX_AGE_SECONDS,
    create_mfa_token,
    create_session_token,
    verify_mfa_token,
)

router = APIRouter()

MFA_COOKIE_NAME = "ansideck_mfa"
MFA_COOKIE_PATH = "/api/auth/login"

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
        totp_enabled=user.totp_enabled,
    )


def _login_key(ip: str, username: str) -> tuple[str, str]:
    return (ip, username.lower()[:150])


def _raise_if_throttled(ip: str, username: str, message: str) -> None:
    if user_login_throttle.blocked(_login_key(ip, username)) or ip_login_throttle.blocked(ip):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS, message, headers={"Retry-After": "300"}
        )


def _record_login_failure(ip: str, username: str) -> None:
    user_login_throttle.record_failure(_login_key(ip, username))
    ip_login_throttle.record_failure(ip)


def _check_current_password(
    db: Session, request: Request, user: User, password: str, action: str
) -> str:
    """Re-authentication for account changes. Guesses share the login throttle: a stolen
    session must not become an unthrottled way to find the password (and keep the
    account for good). Returns the client IP."""
    ip = client_ip(request)
    _raise_if_throttled(
        ip, user.username, "Too many failed password attempts. Try again in a few minutes."
    )
    if not verify_password(password, user.password_hash):
        _record_login_failure(ip, user.username)
        audit.record(
            db,
            action,
            outcome="failure",
            actor=user,
            ip=ip,
            detail={"reason": "wrong current password"},
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Current password is incorrect")
    user_login_throttle.reset(_login_key(ip, user.username))
    return ip


def _check_second_factor(
    db: Session, user: User, ip: str, action: str, *, code: str | None, recovery_code: str | None
) -> str:
    """Throttled per user as well as per (IP, user); returns "totp" or "recovery_code"."""
    if totp_user_throttle.blocked(user.id):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Too many wrong codes. Try again in 15 minutes.",
            headers={"Retry-After": "900"},
        )
    # Lock the row and re-read it, so two requests racing with the same fresh code (or
    # recovery code) are serialised and the second sees the first one's use of it. The
    # lock ends with this request's commit (success) or the failure audit's commit.
    db.refresh(user, with_for_update=True)
    method = totp.use_second_factor(user, code=code, recovery_code=recovery_code)
    if method is None:
        _record_login_failure(ip, user.username)
        totp_user_throttle.record_failure(user.id)
        audit.record(
            db, action, outcome="failure", actor=user, ip=ip, detail={"reason": "bad second factor"}
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "That code is not valid")
    return method


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


@router.post("/login", response_model=UserOut | MfaChallenge)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> UserOut | MfaChallenge:
    ip = client_ip(request)
    _raise_if_throttled(
        ip, payload.username, "Too many failed login attempts. Try again in a few minutes."
    )

    user = db.query(User).filter(User.username == payload.username).first()
    password_ok = verify_password(
        payload.password, user.password_hash if user else _get_dummy_hash()
    )
    if user is None or not password_ok or not user.is_active:
        _record_login_failure(ip, payload.username)
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

    if user.totp_enabled:
        # No session yet, and the throttle isn't reset until the second factor.
        response.set_cookie(
            key=MFA_COOKIE_NAME,
            value=create_mfa_token(user.id, user.session_version),
            httponly=True,
            samesite="lax",
            secure=get_settings().cookie_secure,
            max_age=MFA_MAX_AGE_SECONDS,
            path=MFA_COOKIE_PATH,
        )
        return MfaChallenge()
    user_login_throttle.reset(_login_key(ip, user.username))
    _set_session_cookie(response, user)
    audit.record(db, "auth.login", actor=user, ip=ip)
    return _to_out(db, user)


@router.post("/login/mfa", response_model=UserOut)
def login_mfa(
    payload: MfaLoginRequest,
    request: Request,
    response: Response,
    ansideck_mfa: str | None = Cookie(default=None, alias=MFA_COOKIE_NAME),
    db: Session = Depends(get_db),
) -> UserOut:
    parsed = verify_mfa_token(ansideck_mfa) if ansideck_mfa else None
    user = db.get(User, parsed[0]) if parsed else None
    if (
        user is None
        or not user.is_active
        or user.session_version != parsed[1]
        or not user.totp_enabled
    ):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sign-in expired. Start again.")
    ip = client_ip(request)
    _raise_if_throttled(
        ip, user.username, "Too many failed login attempts. Try again in a few minutes."
    )
    method = _check_second_factor(
        db, user, ip, "auth.login", code=payload.code, recovery_code=payload.recovery_code
    )
    db.commit()
    user_login_throttle.reset(_login_key(ip, user.username))
    totp_user_throttle.reset(user.id)
    response.delete_cookie(MFA_COOKIE_NAME, path=MFA_COOKIE_PATH)
    _set_session_cookie(response, user)
    detail: dict[str, object] = {"mfa": method}
    if method == "recovery_code":
        detail["recovery_codes_left"] = len(user.totp_recovery_hashes or [])
    audit.record(db, "auth.login", actor=user, ip=ip, detail=detail)
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
    ip = _check_current_password(
        db, request, current_user, payload.current_password, "auth.password_change"
    )
    if payload.new_password.lower() == current_user.username.lower():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Password must not equal your username")
    current_user.password_hash = hash_password(payload.new_password)
    current_user.session_version += 1  # signs out every other session
    db.commit()
    _set_session_cookie(response, current_user)  # ...but keep this one
    audit.record(db, "auth.password_change", actor=current_user, ip=ip)
    return {"ok": True}


@router.post("/totp/setup", response_model=TotpSetupOut)
def totp_setup(
    payload: PasswordConfirmRequest,
    request: Request,
    current_user: User = Depends(_authenticated),
    db: Session = Depends(get_db),
) -> TotpSetupOut:
    _check_current_password(db, request, current_user, payload.current_password, "auth.totp_enable")
    if current_user.totp_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "Two-factor login is already on")
    secret = totp.new_secret()
    current_user.totp_pending_secret = totp.encrypt(secret)
    db.commit()
    uri = totp.provisioning_uri(secret, current_user.username)
    return TotpSetupOut(secret=secret, otpauth_uri=uri, qr=totp.qr_data_uri(uri))


@router.post("/totp/enable", response_model=RecoveryCodesOut)
def totp_enable(
    payload: TotpCodeRequest,
    request: Request,
    response: Response,
    current_user: User = Depends(_authenticated),
    db: Session = Depends(get_db),
) -> RecoveryCodesOut:
    if current_user.totp_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "Two-factor login is already on")
    if current_user.totp_pending_secret is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Start the setup first")
    counter = totp.match_counter(totp.decrypt(current_user.totp_pending_secret), payload.code, None)
    if counter is None:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "That code is not valid. Check the time on your device and try the next code.",
        )
    codes = totp.enable(current_user, counter)
    current_user.session_version += 1  # sessions signed in with the password alone end
    db.commit()
    _set_session_cookie(response, current_user)  # ...except this one
    audit.record(db, "auth.totp_enable", actor=current_user, ip=client_ip(request))
    return RecoveryCodesOut(recovery_codes=codes)


@router.post("/totp/disable")
def totp_disable(
    payload: TotpDisableRequest,
    request: Request,
    current_user: User = Depends(_authenticated),
    db: Session = Depends(get_db),
) -> dict[str, bool]:
    ip = _check_current_password(
        db, request, current_user, payload.current_password, "auth.totp_disable"
    )
    if not current_user.totp_enabled:
        return {"ok": True}
    # A 6-digit entry is a TOTP code; anything else is tried as a recovery code.
    is_totp = totp.looks_like_totp_code(payload.code)
    _check_second_factor(
        db,
        current_user,
        ip,
        "auth.totp_disable",
        code=payload.code if is_totp else None,
        recovery_code=None if is_totp else payload.code,
    )
    totp.clear(current_user)
    db.commit()
    audit.record(db, "auth.totp_disable", actor=current_user, ip=ip)
    return {"ok": True}


@router.post("/totp/recovery-codes", response_model=RecoveryCodesOut)
def totp_regenerate_recovery_codes(
    payload: PasswordConfirmRequest,
    request: Request,
    current_user: User = Depends(_authenticated),
    db: Session = Depends(get_db),
) -> RecoveryCodesOut:
    ip = _check_current_password(
        db, request, current_user, payload.current_password, "auth.totp_recovery_regenerate"
    )
    if not current_user.totp_enabled:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Two-factor login is off")
    codes, hashes = totp.new_recovery_codes()
    current_user.totp_recovery_hashes = hashes
    db.commit()
    audit.record(db, "auth.totp_recovery_regenerate", actor=current_user, ip=ip)
    return RecoveryCodesOut(recovery_codes=codes)
