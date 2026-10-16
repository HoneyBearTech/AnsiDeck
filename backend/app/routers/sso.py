from collections.abc import Callable
from dataclasses import dataclass
from types import ModuleType

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app import audit, github_login, oidc
from app.config import Settings, get_settings
from app.db import get_db
from app.hardening import client_ip, sso_ip_throttle
from app.routers.auth import _set_session_cookie
from app.sso_common import (
    STATE_MAX_AGE_SECONDS,
    SsoError,
    audit_membership_changes,
    sync_managed_memberships,
)

# Public on purpose: they run before there is a session. Sign-in only ever ends in a
# redirect to a fixed path, so there is no user-controlled redirect target.
router = APIRouter()


@dataclass(frozen=True)
class Provider:
    """What the shared start/callback handlers need to know about one sign-in flow."""

    module: ModuleType  # begin_login / complete_login / STATE_COOKIE_*
    method: str  # recorded as `detail.method` on auth.login
    enabled: Callable[[Settings], bool]
    issuer: Callable[[Settings], str]
    # Audit wording for memberships its group mapping changes.
    sync_actor: str = "(sso group sync)"
    sync_via: str = "sso group"


_OIDC = Provider(oidc, "sso", lambda s: s.oidc_enabled, lambda s: s.oidc_issuer)
_GITHUB = Provider(
    github_login,
    "github",
    lambda s: s.github_enabled,
    lambda s: s.github_url,
    sync_actor="(github team sync)",
    sync_via="github team",
)


def _require_enabled(provider: Provider) -> Settings:
    settings = get_settings()
    if not provider.enabled(settings):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "SSO is not enabled")
    return settings


def _failure(provider: Provider, code: str) -> RedirectResponse:
    response = RedirectResponse(f"/login?sso_error={code}", status.HTTP_302_FOUND)
    response.delete_cookie(
        provider.module.STATE_COOKIE_NAME, path=provider.module.STATE_COOKIE_PATH
    )
    return response


@router.get("/providers")
def providers() -> dict:
    settings = get_settings()
    rp = settings.passkey_rp
    return {
        "oidc": {"enabled": settings.oidc_enabled, "label": settings.oidc_button_label},
        "github": {"enabled": settings.github_enabled, "label": settings.github_button_label},
        # Passkeys work only at this origin (PUBLIC_URL), the browser's address must match it.
        "passkeys": {
            "enabled": rp is not None,
            "origin": rp[1] if rp is not None else None,
        },
    }


def _login(provider: Provider, request: Request, db: Session) -> RedirectResponse:
    settings = _require_enabled(provider)
    ip = client_ip(request)
    if sso_ip_throttle.blocked(ip):
        return _failure(provider, "failed")
    try:
        url, cookie = provider.module.begin_login(settings)
    except SsoError as exc:
        sso_ip_throttle.record_failure(ip)
        audit.record(
            db,
            "auth.sso",
            outcome="failure",
            actor_username="(sso login start)",
            ip=ip,
            detail={"reason": exc.reason},
        )
        return _failure(provider, exc.code)
    response = RedirectResponse(url, status.HTTP_302_FOUND)
    response.set_cookie(
        key=provider.module.STATE_COOKIE_NAME,
        value=cookie,
        max_age=STATE_MAX_AGE_SECONDS,
        httponly=True,
        samesite="lax",  # the provider's redirect back is a top-level GET
        secure=settings.cookie_secure,
        path=provider.module.STATE_COOKIE_PATH,
    )
    return response


def _callback(
    provider: Provider,
    request: Request,
    db: Session,
    *,
    code: str | None,
    state: str | None,
    error: str | None,
    state_cookie: str | None,
) -> RedirectResponse:
    settings = _require_enabled(provider)
    ip = client_ip(request)
    if sso_ip_throttle.blocked(ip):
        return _failure(provider, "failed")
    try:
        if error or not code or not state or not state_cookie:
            raise SsoError("failed", f"provider error or missing parameters ({error or 'none'})")
        sign_in = provider.module.complete_login(
            db, settings, cookie=state_cookie, code=code, state=state
        )
        user = sign_in.user
        changes, kept = [], []
        if sign_in.grants is not None and sign_in.source is not None:
            try:
                changes, kept = sync_managed_memberships(db, user, sign_in.source, sign_in.grants)
            except SQLAlchemyError as exc:
                raise SsoError("failed", "project membership sync failed", user=user) from exc
    except SsoError as exc:
        sso_ip_throttle.record_failure(ip)
        audit.record(
            db,
            "auth.sso",
            outcome="failure",
            actor=exc.user,
            actor_username=None if exc.user else "(unknown sso identity)",
            ip=ip,
            detail={"reason": exc.reason, "email": exc.email},
        )
        return _failure(provider, exc.code)

    response = RedirectResponse("/", status.HTTP_302_FOUND)
    response.delete_cookie(
        provider.module.STATE_COOKIE_NAME, path=provider.module.STATE_COOKIE_PATH
    )
    _set_session_cookie(response, user, "sso")
    if sign_in.newly_linked:
        audit.record(
            db,
            "auth.sso_link",
            actor=user,
            target_type="user",
            target_id=user.id,
            target_name=user.username,
            ip=ip,
            detail={"issuer": provider.issuer(settings)},
        )
    audit_membership_changes(
        db, user, changes, actor_username=provider.sync_actor, via=provider.sync_via, ip=ip
    )
    detail: dict = {"method": provider.method, **sign_in.notes}
    if kept:
        detail["kept_manual"] = kept
    audit.record(db, "auth.login", actor=user, ip=ip, detail=detail)
    return response


@router.get("/oidc/login")
def oidc_login(request: Request, db: Session = Depends(get_db)) -> RedirectResponse:
    return _login(_OIDC, request, db)


@router.get("/oidc/callback")
def oidc_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    state_cookie: str | None = Cookie(default=None, alias=oidc.STATE_COOKIE_NAME),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    return _callback(
        _OIDC, request, db, code=code, state=state, error=error, state_cookie=state_cookie
    )


@router.get("/github/login")
def github_login_start(request: Request, db: Session = Depends(get_db)) -> RedirectResponse:
    return _login(_GITHUB, request, db)


@router.get("/github/callback")
def github_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    state_cookie: str | None = Cookie(default=None, alias=github_login.STATE_COOKIE_NAME),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    return _callback(
        _GITHUB, request, db, code=code, state=state, error=error, state_cookie=state_cookie
    )
