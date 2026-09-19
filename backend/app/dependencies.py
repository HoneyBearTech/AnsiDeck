from fastapi import Cookie, Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

from app import audit
from app.api_keys import authenticate_api_key
from app.db import get_db
from app.hardening import api_key_ip_throttle, client_ip
from app.models import User
from app.security import verify_session_token

SESSION_COOKIE_NAME = "ansideck_session"


class RateLimited(Exception):
    """Too many bad API keys from this client address."""


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


def _authenticate_bearer(db: Session, authorization: str, ip: str) -> User | None:
    if api_key_ip_throttle.blocked(ip):
        raise RateLimited
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() == "bearer" and token.strip():
        principal, reason, prefix = authenticate_api_key(db, token.strip(), ip)
        if principal is not None:
            return principal
    else:
        reason, prefix = "malformed", None
    api_key_ip_throttle.record_failure(ip)
    # Only the public prefix is recorded — never any part of the presented secret.
    audit.record(
        db,
        "apikey.auth",
        outcome="failure",
        actor_username=f"apikey:{prefix}" if prefix else "(malformed key)",
        ip=ip,
        detail={"reason": reason},
    )
    return None


def authenticate_request(
    db: Session, *, cookie_token: str | None, authorization: str | None, ip: str
) -> User | None:
    """The session user, or an API-key principal. An Authorization header is used
    exclusively: a bad key never falls back to a valid cookie. Raises RateLimited."""
    if authorization is not None:
        return _authenticate_bearer(db, authorization, ip)
    return authenticate_token(db, cookie_token)


def get_current_user(
    request: Request,
    ansideck_session: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME),
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> User:
    if not ansideck_session and authorization is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    try:
        user = authenticate_request(
            db,
            cookie_token=ansideck_session,
            authorization=authorization,
            ip=client_ip(request),
        )
    except RateLimited:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Too many invalid API keys. Try again in a few minutes.",
            headers={"Retry-After": "300"},
        ) from None
    if user is None:
        if authorization is not None:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                "Invalid API key",
                headers={"WWW-Authenticate": "Bearer"},
            )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session invalid or expired")
    return user
