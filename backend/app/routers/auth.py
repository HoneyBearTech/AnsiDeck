import functools
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app import audit, passkeys, totp
from app.config import get_settings
from app.crypto import hash_password, verify_password
from app.db import get_db
from app.dependencies import SESSION_COOKIE_NAME, authenticate_token
from app.hardening import client_ip, ip_login_throttle, totp_user_throttle, user_login_throttle
from app.models import Project, User, WebAuthnCredential
from app.permissions import (
    admin_2fa_required,
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
    PasskeyAddedOut,
    PasskeyCredentialIn,
    PasskeyOptionsOut,
    PasskeyOut,
    PasskeyRegisterRequest,
    PasskeyRenameRequest,
    PasswordConfirmRequest,
    ProjectAccess,
    RecoveryCodesOut,
    RemovePasskeyRequest,
    TotpCodeRequest,
    TotpDisableRequest,
    TotpSetupOut,
    UserOut,
)
from app.security import (
    MFA_MAX_AGE_SECONDS,
    SESSION_MAX_AGE_SECONDS,
    SignInMethod,
    create_mfa_token,
    create_session_token,
    session_info,
    verify_mfa_token,
)
from app.sso_common import audit_membership_changes, drop_managed_memberships

router = APIRouter()

MFA_COOKIE_NAME = "ansideck_mfa"
MFA_COOKIE_PATH = "/api/auth/login"

_authenticated = require_authenticated()
# REQUIRE_ADMIN_2FA: what an admin without a second factor may still do (pinned by a test).
_setting_up = require_authenticated(during_2fa_setup=True)

# An SSO session this young counts as re-authentication: SSO users may never have been told the
# password an admin set for them.
RECENT_SSO_SIGN_IN = timedelta(minutes=15)


# Verified against when the username doesn't exist, so an unknown user costs the
# same argon2 time as a wrong password (no timing/enumeration oracle).
@functools.cache
def _get_dummy_hash() -> str:
    return hash_password("ansideck-dummy-password")


def _to_out(db: Session, user: User, signed_in_with: SignInMethod = "password") -> UserOut:
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
        passkey_count=len(user.passkeys),
        two_factor_enabled=user.two_factor_enabled,
        two_factor_setup_required=signed_in_with == "password"
        and not user.two_factor_enabled
        and admin_2fa_required(db, user),
        signed_in_with=signed_in_with,
    )


def _refuse_removing_last_factor(db: Session, user: User, removing: str) -> None:
    """An admin under REQUIRE_ADMIN_2FA keeps at least one second factor."""
    left = (
        (1 if user.totp_enabled and removing != "totp" else 0)
        + len(user.passkeys)
        - (1 if removing == "passkey" else 0)
    )
    if left == 0 and admin_2fa_required(db, user):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Admins must keep a second factor here: add another one before removing this one",
        )


def _methods(user: User) -> list[str]:
    """The second factors this user can sign in with now."""
    methods = ["totp"] if user.totp_enabled else []
    if user.passkeys and get_settings().passkey_rp is not None:
        methods.append("passkey")
    return [*methods, "recovery_code"]


def _passkey_out(passkey: WebAuthnCredential) -> PasskeyOut:
    return PasskeyOut(
        id=passkey.id,
        name=passkey.name,
        created_at=passkey.created_at,
        last_used_at=passkey.last_used_at,
        synced=passkey.backup_eligible,
    )


def _login_key(ip: str, username: str) -> tuple[str, str]:
    return (ip, username.lower()[:150])


def _raise_if_throttled(ip: str, username: str, message: str) -> None:
    if user_login_throttle.blocked(_login_key(ip, username)) or ip_login_throttle.blocked(ip):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS, message, headers={"Retry-After": "300"}
        )


def _record_login_failure(ip: str, username: str) -> bool:
    """Counts a failed attempt; True if it locked the user name or the address out (the
    audit event says so, and app.notifications reports it as a login attack)."""
    user_login_throttle.record_failure(_login_key(ip, username))
    ip_login_throttle.record_failure(ip)
    return user_login_throttle.blocked(_login_key(ip, username)) or ip_login_throttle.blocked(ip)


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
        locked_out = _record_login_failure(ip, user.username)
        audit.record(
            db,
            action,
            outcome="failure",
            actor=user,
            ip=ip,
            detail={
                "reason": "wrong current password",
                **({"locked_out": True} if locked_out else {}),
            },
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Current password is incorrect")
    user_login_throttle.reset(_login_key(ip, user.username))
    return ip


def check_reauthentication(
    db: Session, request: Request, user: User, current_password: str | None, action: str
) -> str:
    """For actions that hand out lasting access: the current password, or a session that SSO
    started within RECENT_SSO_SIGN_IN. Returns the client IP; refusals are audited."""
    if current_password is not None:
        return _check_current_password(db, request, user, current_password, action)
    ip = client_ip(request)
    info = session_info(request.cookies.get(SESSION_COOKIE_NAME, ""))
    if info and info.method == "sso":
        if datetime.now(UTC) - info.issued_at <= RECENT_SSO_SIGN_IN:
            return ip
        reason, message = (
            "sso sign-in too old",
            "Sign in with single sign-on again (or enter your password), then try again.",
        )
    else:
        reason, message = "no current password", "Enter your current password."
    audit.record(db, action, outcome="failure", actor=user, ip=ip, detail={"reason": reason})
    raise HTTPException(status.HTTP_401_UNAUTHORIZED, message)


def _check_second_factor_throttle(user: User) -> None:
    if totp_user_throttle.blocked(user.id):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Too many failed attempts. Try again in 15 minutes.",
            headers={"Retry-After": "900"},
        )


def _check_second_factor(
    db: Session,
    user: User,
    ip: str,
    action: str,
    *,
    code: str | None = None,
    recovery_code: str | None = None,
    passkey: dict | None = None,
    purpose: str = "login",
) -> str:
    """A TOTP code, a recovery code or a passkey response (to options for `purpose`),
    throttled per user (all of them together) as well as per (IP, user); returns "totp",
    "recovery_code" or "passkey"."""
    _check_second_factor_throttle(user)
    # Lock the row and re-read it, so two requests racing with the same fresh code (or
    # recovery code, or passkey challenge) are serialised and the second sees the first one's
    # use of it. The lock ends with this request's commit or the failure audit's commit.
    db.refresh(user, with_for_update=True)
    problem, message = None, "That code is not valid"
    if passkey is not None:
        try:
            passkeys.verify_assertion(user, passkey, purpose)
            method: str | None = "passkey"
        except passkeys.PasskeyError as exc:
            method, problem, message = None, exc.reason, str(exc)
    else:
        method = totp.use_second_factor(user, code=code, recovery_code=recovery_code)
    if method is None:
        locked_out = _record_login_failure(ip, user.username)
        totp_user_throttle.record_failure(user.id)
        locked_out = locked_out or totp_user_throttle.blocked(user.id)
        audit.record(
            db,
            action,
            outcome="failure",
            actor=user,
            ip=ip,
            detail={
                "reason": "bad second factor",
                **({"passkey_problem": problem} if problem else {}),
                **({"locked_out": True} if locked_out else {}),
            },
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, message)
    return method


def _check_proof(
    db: Session, user: User, ip: str, action: str, code: str | None, assertion: dict | None
) -> str:
    """A current second factor for removing one (a 6-digit entry is a TOTP code, anything
    else a recovery code), or a passkey response to step-up options."""
    if assertion is not None:
        return _check_second_factor(db, user, ip, action, passkey=assertion, purpose="step_up")
    is_totp = totp.looks_like_totp_code(code or "")
    return _check_second_factor(
        db,
        user,
        ip,
        action,
        code=code if is_totp else None,
        recovery_code=None if is_totp else code,
    )


def _drop_sso_memberships(db: Session, user: User, ip: str) -> None:
    """Memberships a sign-in provider (a GitHub team mapping) granted last only while the user
    signs in through it: a password sign-in can't tell whether they are still in the team, so
    they go (and come back at the next sign-in through the provider)."""
    changes = drop_managed_memberships(db, user)
    audit_membership_changes(db, user, changes, actor=user, via="password sign-in", ip=ip)


def _set_session_cookie(response: Response, user: User, method: SignInMethod = "password") -> None:
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=create_session_token(user.id, user.session_version, method),
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
        locked_out = _record_login_failure(ip, payload.username)
        # Only real usernames are recorded verbatim, so attackers can't fill the
        # audit table with arbitrary strings; writes are bounded by the IP throttle.
        audit.record(
            db,
            "auth.login",
            outcome="failure",
            actor_username=user.username if user else "(unknown user)",
            ip=ip,
            detail={
                "reason": "inactive" if user and password_ok else "bad credentials",
                **({"locked_out": True} if locked_out else {}),
            },
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password")

    if user.two_factor_enabled:
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
        return MfaChallenge(methods=_methods(user))
    user_login_throttle.reset(_login_key(ip, user.username))
    _drop_sso_memberships(db, user, ip)
    _set_session_cookie(response, user)
    out = _to_out(db, user)
    detail = {"two_factor_setup_required": True} if out.two_factor_setup_required else None
    audit.record(db, "auth.login", actor=user, ip=ip, detail=detail)
    return out


def _mfa_user(db: Session, ansideck_mfa: str | None, ip: str) -> User:
    """The user whose password was right (the MFA cookie), if they still may sign in."""
    parsed = verify_mfa_token(ansideck_mfa) if ansideck_mfa else None
    user = db.get(User, parsed[0]) if parsed else None
    if (
        user is None
        or not user.is_active
        or user.session_version != parsed[1]
        or not user.two_factor_enabled
    ):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sign-in expired. Start again.")
    _raise_if_throttled(
        ip, user.username, "Too many failed login attempts. Try again in a few minutes."
    )
    return user


@router.post("/login/mfa", response_model=UserOut)
def login_mfa(
    payload: MfaLoginRequest,
    request: Request,
    response: Response,
    ansideck_mfa: str | None = Cookie(default=None, alias=MFA_COOKIE_NAME),
    db: Session = Depends(get_db),
) -> UserOut:
    ip = client_ip(request)
    user = _mfa_user(db, ansideck_mfa, ip)
    method = _check_second_factor(
        db, user, ip, "auth.login", code=payload.code, recovery_code=payload.recovery_code
    )
    return _finish_mfa(db, response, user, ip, method)


@router.post("/login/mfa/passkey/options", response_model=PasskeyOptionsOut)
def login_passkey_options(
    request: Request,
    ansideck_mfa: str | None = Cookie(default=None, alias=MFA_COOKIE_NAME),
    db: Session = Depends(get_db),
) -> PasskeyOptionsOut:
    """Options for navigator.credentials.get() with the user's passkeys (the password was
    right: the MFA cookie)."""
    user = _mfa_user(db, ansideck_mfa, client_ip(request))
    _check_second_factor_throttle(user)
    db.refresh(user, with_for_update=True)
    try:
        options = passkeys.authentication_options(user, "login")
    except passkeys.PasskeyError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from None
    db.commit()
    return PasskeyOptionsOut(options=options)


@router.post("/login/mfa/passkey", response_model=UserOut)
def login_passkey(
    payload: PasskeyCredentialIn,
    request: Request,
    response: Response,
    ansideck_mfa: str | None = Cookie(default=None, alias=MFA_COOKIE_NAME),
    db: Session = Depends(get_db),
) -> UserOut:
    ip = client_ip(request)
    user = _mfa_user(db, ansideck_mfa, ip)
    method = _check_second_factor(db, user, ip, "auth.login", passkey=payload.credential)
    return _finish_mfa(db, response, user, ip, method)


def _finish_mfa(db: Session, response: Response, user: User, ip: str, method: str) -> UserOut:
    db.commit()
    user_login_throttle.reset(_login_key(ip, user.username))
    totp_user_throttle.reset(user.id)
    response.delete_cookie(MFA_COOKIE_NAME, path=MFA_COOKIE_PATH)
    _drop_sso_memberships(db, user, ip)
    _set_session_cookie(response, user)
    detail: dict[str, object] = {"mfa": method}
    if method == "recovery_code":
        detail["recovery_codes_left"] = len(user.recovery_code_hashes or [])
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
def me(
    request: Request, current_user: User = Depends(_setting_up), db: Session = Depends(get_db)
) -> UserOut:
    info = session_info(request.cookies.get(SESSION_COOKIE_NAME, ""))
    return _to_out(db, current_user, info.method if info else "password")


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
    current_user: User = Depends(_setting_up),
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
    current_user: User = Depends(_setting_up),
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
    _refuse_removing_last_factor(db, current_user, "totp")
    _check_proof(db, current_user, ip, "auth.totp_disable", payload.code, payload.passkey)
    totp.clear(current_user)
    db.commit()
    audit.record(
        db,
        "auth.totp_disable",
        actor=current_user,
        ip=ip,
        detail={"two_factor_off": not current_user.two_factor_enabled},
    )
    return {"ok": True}


@router.post("/recovery-codes", response_model=RecoveryCodesOut)
def regenerate_recovery_codes(
    payload: PasswordConfirmRequest,
    request: Request,
    current_user: User = Depends(_authenticated),
    db: Session = Depends(get_db),
) -> RecoveryCodesOut:
    """New recovery codes (for TOTP and passkeys alike); the old ones stop working."""
    ip = _check_current_password(
        db, request, current_user, payload.current_password, "auth.recovery_codes_regenerate"
    )
    if not current_user.two_factor_enabled:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Two-factor login is off")
    codes, current_user.recovery_code_hashes = totp.new_recovery_codes()
    db.commit()
    audit.record(db, "auth.recovery_codes_regenerate", actor=current_user, ip=ip)
    return RecoveryCodesOut(recovery_codes=codes)


@router.post("/totp/recovery-codes", response_model=RecoveryCodesOut, deprecated=True)
def totp_regenerate_recovery_codes(
    payload: PasswordConfirmRequest,
    request: Request,
    current_user: User = Depends(_authenticated),
    db: Session = Depends(get_db),
) -> RecoveryCodesOut:
    """Deprecated: POST /api/auth/recovery-codes."""
    return regenerate_recovery_codes(payload, request, current_user, db)


# ------------------------------------------------------------------ passkeys


def _passkey(user: User, passkey_id: int) -> WebAuthnCredential:
    found = next((p for p in user.passkeys if p.id == passkey_id), None)
    if found is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Passkey not found")
    return found


@router.get("/passkeys", response_model=list[PasskeyOut])
def list_passkeys(current_user: User = Depends(_setting_up)) -> list[PasskeyOut]:
    return [_passkey_out(p) for p in current_user.passkeys]


@router.post("/passkeys/registration/options", response_model=PasskeyOptionsOut)
def passkey_registration_options(
    payload: PasswordConfirmRequest,
    request: Request,
    current_user: User = Depends(_setting_up),
    db: Session = Depends(get_db),
) -> PasskeyOptionsOut:
    """Options for navigator.credentials.create() (adding a passkey asks for the password)."""
    _check_current_password(db, request, current_user, payload.current_password, "auth.passkey_add")
    db.refresh(current_user, with_for_update=True)
    try:
        options = passkeys.registration_options(current_user)
    except passkeys.PasskeysUnavailable as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from None
    except passkeys.PasskeyError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from None
    db.commit()
    return PasskeyOptionsOut(options=options)


@router.post("/passkeys", response_model=PasskeyAddedOut, status_code=status.HTTP_201_CREATED)
def add_passkey(
    payload: PasskeyRegisterRequest,
    request: Request,
    response: Response,
    current_user: User = Depends(_setting_up),
    db: Session = Depends(get_db),
) -> PasskeyAddedOut:
    """Stores the passkey navigator.credentials.create() made for the options above. The first
    second factor comes with recovery codes and signs out the other sessions."""
    ip = client_ip(request)
    db.refresh(current_user, with_for_update=True)
    if any(p.name == payload.name for p in current_user.passkeys):
        raise HTTPException(status.HTTP_409_CONFLICT, "You already have a passkey with that name")
    try:
        new = passkeys.verify_registration(current_user, payload.credential)
    except passkeys.PasskeyError as exc:
        db.commit()  # the challenge is used up
        audit.record(
            db, "auth.passkey_add", outcome="failure", actor=current_user, ip=ip,
            detail={"reason": exc.reason},
        )  # fmt: skip
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from None
    if db.query(WebAuthnCredential).filter_by(credential_id=new.credential_id).first():
        db.commit()
        raise HTTPException(status.HTTP_409_CONFLICT, "That passkey is already registered")
    first = not current_user.two_factor_enabled
    passkey = WebAuthnCredential(
        user_id=current_user.id,
        name=payload.name,
        credential_id=new.credential_id,
        public_key=new.public_key,
        sign_count=new.sign_count,
        transports=new.transports,
        aaguid=new.aaguid,
        backup_eligible=new.backup_eligible,
        backed_up=new.backed_up,
    )
    current_user.passkeys.append(passkey)
    codes = None
    if first:
        codes, current_user.recovery_code_hashes = totp.new_recovery_codes()
        current_user.session_version += 1  # sessions signed in with the password alone end
    db.commit()
    db.refresh(passkey)
    if first:
        _set_session_cookie(response, current_user)  # ...except this one
    audit.record(
        db, "auth.passkey_add", actor=current_user, ip=ip,
        detail={"passkey_id": passkey.id, "name": passkey.name, "aaguid": passkey.aaguid},
    )  # fmt: skip
    return PasskeyAddedOut(passkey=_passkey_out(passkey), recovery_codes=codes)


@router.patch("/passkeys/{passkey_id}", response_model=PasskeyOut)
def rename_passkey(
    passkey_id: int,
    payload: PasskeyRenameRequest,
    request: Request,
    current_user: User = Depends(_authenticated),
    db: Session = Depends(get_db),
) -> PasskeyOut:
    passkey = _passkey(current_user, passkey_id)
    name = payload.name.strip()
    if not name:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "A name is required")
    if any(p.name == name and p.id != passkey.id for p in current_user.passkeys):
        raise HTTPException(status.HTTP_409_CONFLICT, "You already have a passkey with that name")
    old, passkey.name = passkey.name, name
    db.commit()
    audit.record(
        db, "auth.passkey_rename", actor=current_user, ip=client_ip(request),
        detail={"passkey_id": passkey.id, "name": name, "was": old},
    )  # fmt: skip
    return _passkey_out(passkey)


@router.post("/passkeys/step-up-options", response_model=PasskeyOptionsOut)
def passkey_step_up_options(
    current_user: User = Depends(_authenticated), db: Session = Depends(get_db)
) -> PasskeyOptionsOut:
    """Options to confirm a change (removing a second factor) with one of your passkeys."""
    _check_second_factor_throttle(current_user)
    db.refresh(current_user, with_for_update=True)
    try:
        options = passkeys.authentication_options(current_user, "step_up")
    except passkeys.PasskeyError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from None
    db.commit()
    return PasskeyOptionsOut(options=options)


@router.post("/passkeys/{passkey_id}/remove")
def remove_passkey(
    passkey_id: int,
    payload: RemovePasskeyRequest,
    request: Request,
    current_user: User = Depends(_authenticated),
    db: Session = Depends(get_db),
) -> dict[str, bool]:
    """Removes a passkey: the password and a current second factor (a code, a recovery code
    or a passkey, maybe this one). The last second factor takes the recovery codes with it."""
    ip = _check_current_password(
        db, request, current_user, payload.current_password, "auth.passkey_remove"
    )
    passkey = _passkey(current_user, passkey_id)
    _refuse_removing_last_factor(db, current_user, "passkey")
    _check_proof(db, current_user, ip, "auth.passkey_remove", payload.code, payload.passkey)
    detail = {"passkey_id": passkey.id, "name": passkey.name}
    current_user.passkeys.remove(passkey)
    db.flush()
    if not current_user.two_factor_enabled:
        current_user.recovery_code_hashes = None
    db.commit()
    audit.record(
        db, "auth.passkey_remove", actor=current_user, ip=ip,
        detail={**detail, "two_factor_off": not current_user.two_factor_enabled},
    )  # fmt: skip
    return {"ok": True}
