"""Native "Sign in with GitHub" (OAuth 2.0 authorization code + PKCE + state).

GitHub is not an OpenID Connect provider (no ID token, no discovery), so this proves
identity the OAuth way: exchange the code, then ask the API who the token belongs to.
Success ends in the app's normal session cookie via the account model shared with OIDC
(`sso_common.resolve_user`): pre-provisioned users only, matched on the stable numeric
GitHub id once linked, and on a *verified* email the first time. Roles and projects stay
inside AnsiDeck. The access token is used for two reads and then revoked; it is never
stored, logged or audited.
"""

import secrets
from urllib.parse import urlencode

import httpx
from sqlalchemy.orm import Session

from app.config import Settings
from app.models import User
from app.sso_common import (
    SsoError,
    http_client,
    pkce_challenge,
    resolve_user,
    sign_state,
    verify_state,
)

FLOW = "github"
STATE_COOKIE_NAME = "ansideck_gh"
STATE_COOKIE_PATH = "/api/auth/github"
CALLBACK_PATH = "/api/auth/github/callback"
SCOPE = "read:user user:email"
_API_HEADERS = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}


def redirect_uri(settings: Settings) -> str:
    return f"{settings.public_url}{CALLBACK_PATH}"


def begin_login(settings: Settings) -> tuple[str, str]:
    """Returns (GitHub authorization URL, signed state-cookie value)."""
    state = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    query = urlencode(
        {
            "client_id": settings.github_client_id,
            "redirect_uri": redirect_uri(settings),
            "scope": SCOPE,
            "state": state,
            "code_challenge": pkce_challenge(verifier),
            "code_challenge_method": "S256",
            "allow_signup": "false",  # signing up at GitHub is not what this button is for
        }
    )
    url = f"{settings.github_url}/login/oauth/authorize?{query}"
    return url, sign_state(FLOW, {"s": state, "v": verifier})


def _exchange_code(settings: Settings, code: str, verifier: str) -> str:
    form = {
        "client_id": settings.github_client_id,
        "client_secret": settings.github_client_secret,
        "code": code,
        "redirect_uri": redirect_uri(settings),
        "code_verifier": verifier,
    }
    try:
        with http_client() as client:
            response = client.post(
                f"{settings.github_url}/login/oauth/access_token",
                data=form,
                headers={"Accept": "application/json"},
            )
        payload = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise SsoError("failed", f"token request failed: {type(exc).__name__}") from exc
    if not isinstance(payload, dict):
        raise SsoError("failed", "token endpoint returned something other than an object")
    # GitHub reports a bad or expired code as HTTP 200 with an `error` in the body, so the
    # status alone says nothing.
    if payload.get("error"):
        raise SsoError("failed", f"token endpoint refused the code ({payload['error']})")
    token = payload.get("access_token")
    if response.status_code != 200 or not isinstance(token, str) or not token:
        raise SsoError(
            "failed", f"token endpoint gave no access token (HTTP {response.status_code})"
        )
    return token


def _api_get(settings: Settings, token: str, path: str, params: dict | None = None):
    try:
        with http_client() as client:
            response = client.get(
                f"{settings.github_api_url}{path}",
                params=params,
                headers={**_API_HEADERS, "Authorization": f"Bearer {token}"},
            )
        if response.status_code != 200:
            raise SsoError("failed", f"GitHub refused GET {path} (HTTP {response.status_code})")
        return response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise SsoError("failed", f"GitHub request {path} failed: {type(exc).__name__}") from exc


def _subject(settings: Settings, token: str) -> str:
    profile = _api_get(settings, token, "/user")
    user_id = profile.get("id") if isinstance(profile, dict) else None
    # The numeric id is the stable identity; `login` can be renamed and then reissued to
    # someone else, so it is never used. (bool is an int subclass, hence the check.)
    if not isinstance(user_id, int) or isinstance(user_id, bool):
        raise SsoError("failed", "GitHub profile has no numeric id")
    return str(user_id)


def _verified_emails(settings: Settings, token: str) -> list[str]:
    entries = _api_get(settings, token, "/user/emails", {"per_page": 100})
    if not isinstance(entries, list):
        raise SsoError("failed", "unexpected response from GitHub /user/emails")
    return [
        entry["email"].strip()
        for entry in entries
        if isinstance(entry, dict)
        and entry.get("verified") is True
        and isinstance(entry.get("email"), str)
        and "@" in entry["email"]
    ]


def _revoke(settings: Settings, token: str) -> None:
    """Best-effort: OAuth App tokens don't expire, and we have no further use for this one."""
    try:
        with http_client() as client:
            client.request(
                "DELETE",
                f"{settings.github_api_url}/applications/{settings.github_client_id}/token",
                json={"access_token": token},
                auth=(settings.github_client_id, settings.github_client_secret),
                headers=_API_HEADERS,
            )
    except httpx.HTTPError:
        pass


def complete_login(
    db: Session, settings: Settings, *, cookie: str, code: str, state: str
) -> tuple[User, bool]:
    data = verify_state(FLOW, cookie, state)
    verifier = data.get("v")
    if not isinstance(verifier, str):
        raise SsoError("failed", "state cookie missing, invalid or expired")

    token = _exchange_code(settings, code, verifier)
    try:
        subject = _subject(settings, token)
        emails = _verified_emails(settings, token)
    finally:
        _revoke(settings, token)
    if not emails:
        raise SsoError("not_linked", "GitHub account has no verified email")
    return resolve_user(db, settings, settings.github_url, subject, emails)
