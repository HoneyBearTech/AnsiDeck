from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app import audit, oidc
from app.config import get_settings
from app.db import get_db
from app.hardening import client_ip, sso_ip_throttle
from app.routers.auth import _set_session_cookie

# Public on purpose: they run before there is a session. Sign-in only ever ends in a
# redirect to a fixed path, so there is no user-controlled redirect target.
router = APIRouter()


def _require_enabled() -> None:
    if not get_settings().oidc_enabled:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "SSO is not enabled")


def _failure(code: str) -> RedirectResponse:
    response = RedirectResponse(f"/login?sso_error={code}", status.HTTP_302_FOUND)
    response.delete_cookie(oidc.STATE_COOKIE_NAME, path=oidc.STATE_COOKIE_PATH)
    return response


@router.get("/providers")
def providers() -> dict:
    settings = get_settings()
    return {"oidc": {"enabled": settings.oidc_enabled, "label": settings.oidc_button_label}}


@router.get("/oidc/login")
def oidc_login(request: Request, db: Session = Depends(get_db)) -> RedirectResponse:
    _require_enabled()
    settings = get_settings()
    ip = client_ip(request)
    if sso_ip_throttle.blocked(ip):
        return _failure("failed")
    try:
        url, cookie = oidc.begin_login(settings)
    except oidc.SsoError as exc:
        sso_ip_throttle.record_failure(ip)
        audit.record(
            db,
            "auth.sso",
            outcome="failure",
            actor_username="(sso login start)",
            ip=ip,
            detail={"reason": exc.reason},
        )
        return _failure(exc.code)
    response = RedirectResponse(url, status.HTTP_302_FOUND)
    response.set_cookie(
        key=oidc.STATE_COOKIE_NAME,
        value=cookie,
        max_age=oidc.STATE_MAX_AGE_SECONDS,
        httponly=True,
        samesite="lax",  # the provider's redirect back is a top-level GET
        secure=settings.cookie_secure,
        path=oidc.STATE_COOKIE_PATH,
    )
    return response


@router.get("/oidc/callback")
def oidc_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    state_cookie: str | None = Cookie(default=None, alias=oidc.STATE_COOKIE_NAME),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    _require_enabled()
    settings = get_settings()
    ip = client_ip(request)
    if sso_ip_throttle.blocked(ip):
        return _failure("failed")
    try:
        if error or not code or not state or not state_cookie:
            raise oidc.SsoError(
                "failed", f"provider error or missing parameters ({error or 'none'})"
            )
        user, newly_linked = oidc.complete_login(
            db, settings, cookie=state_cookie, code=code, state=state
        )
    except oidc.SsoError as exc:
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
        return _failure(exc.code)

    response = RedirectResponse("/", status.HTTP_302_FOUND)
    response.delete_cookie(oidc.STATE_COOKIE_NAME, path=oidc.STATE_COOKIE_PATH)
    _set_session_cookie(response, user)
    if newly_linked:
        audit.record(
            db,
            "auth.sso_link",
            actor=user,
            target_type="user",
            target_id=user.id,
            target_name=user.username,
            ip=ip,
            detail={"issuer": settings.oidc_issuer},
        )
    audit.record(db, "auth.login", actor=user, ip=ip, detail={"method": "sso"})
    return response
