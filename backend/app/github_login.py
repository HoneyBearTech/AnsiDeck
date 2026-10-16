"""Native "Sign in with GitHub" (OAuth 2.0 authorization code + PKCE + state).

GitHub is not an OpenID Connect provider (no ID token, no discovery), so this proves
identity the OAuth way: exchange the code, then ask the API who the token belongs to.
Success ends in the app's normal session cookie via the account model shared with OIDC
(`sso_common.resolve_user`): pre-provisioned users only, matched on the stable numeric
GitHub id once linked, and on a *verified* email the first time. The access token is used
for a few reads and then revoked; it is never stored, logged or audited.

Optionally (GITHUB_ALLOWED_ORGS / GITHUB_ALLOWED_TEAMS) only active members of an allowed org,
or direct members of an allowed team, get in, checked at every sign-in. GITHUB_TEAM_ROLE_MAP
turns the user's teams into project memberships, which the sign-in router applies.
"""

import secrets
from typing import Literal
from urllib.parse import quote, urlencode

import httpx
from sqlalchemy.orm import Session

from app.config import Settings
from app.models import User
from app.sso_common import (
    SsoError,
    SsoSignIn,
    desired_memberships,
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
SOURCE = "github"  # project_members.granted_by of the memberships the team mapping manages
BASE_SCOPE = "read:user user:email"
ORG_SCOPE = "read:org"
# /user/teams pages of 100; a user in more teams than this is refused rather than half-read.
MAX_TEAM_PAGES = 10
_RESTRICTED = "OAuth App access restrictions"  # in GitHub's 403 message for such an org
_API_HEADERS = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}


def redirect_uri(settings: Settings) -> str:
    return f"{settings.public_url}{CALLBACK_PATH}"


def scope(settings: Settings) -> str:
    """read:org only when an org or team is checked: otherwise nothing needs it."""
    return f"{BASE_SCOPE} {ORG_SCOPE}" if settings.github_needs_org_data else BASE_SCOPE


def begin_login(settings: Settings) -> tuple[str, str]:
    """Returns (GitHub authorization URL, signed state-cookie value)."""
    state = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    query = urlencode(
        {
            "client_id": settings.github_client_id,
            "redirect_uri": redirect_uri(settings),
            "scope": scope(settings),
            "state": state,
            "code_challenge": pkce_challenge(verifier),
            "code_challenge_method": "S256",
            "allow_signup": "false",  # signing up at GitHub is not what this button is for
        }
    )
    url = f"{settings.github_url}/login/oauth/authorize?{query}"
    return url, sign_state(FLOW, {"s": state, "v": verifier})


def _exchange_code(settings: Settings, code: str, verifier: str) -> tuple[str, set[str]]:
    """(access token, the scopes the user actually granted: they can untick one)."""
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
    granted = payload.get("scope")
    scopes = {s.strip() for s in granted.split(",")} if isinstance(granted, str) else set()
    return token, scopes


def _request(
    client: httpx.Client, settings: Settings, token: str, path: str, params: dict | None = None
) -> httpx.Response:
    try:
        return client.get(
            f"{settings.github_api_url}{path}",
            params=params,
            headers={**_API_HEADERS, "Authorization": f"Bearer {token}"},
        )
    except httpx.HTTPError as exc:
        raise SsoError("failed", f"GitHub request {path} failed: {type(exc).__name__}") from exc


def _json(response: httpx.Response, path: str):
    try:
        return response.json()
    except ValueError as exc:
        raise SsoError("failed", f"GitHub request {path} failed: {type(exc).__name__}") from exc


def _api_get(
    client: httpx.Client, settings: Settings, token: str, path: str, params: dict | None = None
):
    response = _request(client, settings, token, path, params)
    if response.status_code != 200:
        raise SsoError("failed", f"GitHub refused GET {path} (HTTP {response.status_code})")
    return _json(response, path)


OrgState = Literal["active", "pending", "none", "restricted", "forbidden"]


def _org_state(client: httpx.Client, settings: Settings, token: str, org: str) -> OrgState:
    """The user's membership of `org`, as GET /user/memberships/orgs/{org} tells it. Anything
    it can't be sure of fails the sign-in rather than counting as a membership."""
    path = f"/user/memberships/orgs/{quote(org, safe='')}"
    response = _request(client, settings, token, path)
    if response.status_code == 404:
        return "none"
    if response.status_code == 403:
        if response.headers.get("x-ratelimit-remaining") == "0":
            raise SsoError("failed", "GitHub rate limit reached")
        body = _json(response, path)
        message = body.get("message") if isinstance(body, dict) else None
        if isinstance(message, str) and _RESTRICTED in message:
            return "restricted"
        return "forbidden"
    if response.status_code != 200:
        raise SsoError(
            "failed", f"GitHub membership check for org {org} failed (HTTP {response.status_code})"
        )
    body = _json(response, path)
    state = body.get("state") if isinstance(body, dict) else None
    if state == "active":
        return "active"
    return "pending" if state == "pending" else "none"


def _user_teams(client: httpx.Client, settings: Settings, token: str) -> set[str]:
    """The user's teams as "org/slug", lowercased. Pages are asked for by number: a Link
    header's URL is never followed, so the token only ever goes to GITHUB_API_URL."""
    teams: set[str] = set()
    for page in range(1, MAX_TEAM_PAGES + 1):
        entries = _api_get(client, settings, token, "/user/teams", {"per_page": 100, "page": page})
        if not isinstance(entries, list):
            raise SsoError("failed", "unexpected response from GitHub /user/teams")
        for entry in entries:
            org = entry.get("organization") if isinstance(entry, dict) else None
            login = org.get("login") if isinstance(org, dict) else None
            slug = entry.get("slug") if isinstance(entry, dict) else None
            if isinstance(login, str) and isinstance(slug, str):
                teams.add(f"{login.lower()}/{slug.lower()}")
        if len(entries) < 100:
            return teams
    raise SsoError("failed", f"more than {MAX_TEAM_PAGES * 100} GitHub teams; refusing to guess")


def _subject(client: httpx.Client, settings: Settings, token: str) -> str:
    profile = _api_get(client, settings, token, "/user")
    user_id = profile.get("id") if isinstance(profile, dict) else None
    # The numeric id is the stable identity; `login` can be renamed and then reissued to
    # someone else, so it is never used. (bool is an int subclass, hence the check.)
    if not isinstance(user_id, int) or isinstance(user_id, bool):
        raise SsoError("failed", "GitHub profile has no numeric id")
    return str(user_id)


def _verified_emails(client: httpx.Client, settings: Settings, token: str) -> list[str]:
    entries = _api_get(client, settings, token, "/user/emails", {"per_page": 100})
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


def _check_gate(
    db: Session, settings: Settings, subject: str, orgs: dict[str, OrgState], teams: set[str]
) -> str:
    """What lets the user in ("org acme" / "team acme/ops"), or SsoError "not_allowed"."""
    for org in settings.github_allowed_orgs:
        if orgs.get(org) == "active":
            return f"org {org}"
    for team in settings.github_allowed_teams:
        if team in teams:
            return f"team {team}"
    checked = [
        *settings.github_allowed_orgs,
        *(t.split("/")[0] for t in settings.github_allowed_teams),
    ]
    restricted = sorted({org for org in checked if orgs.get(org) == "restricted"})
    pending = sorted({org for org in checked if orgs.get(org) == "pending"})
    if restricted:
        reason = (
            f"GitHub org {', '.join(restricted)} restricts OAuth apps: an org owner must approve "
            "AnsiDeck's OAuth app (org settings, Third-party access)"
        )
    elif pending:
        reason = (
            f"membership of GitHub org {', '.join(pending)} is pending (invitation not accepted)"
        )
    else:
        reason = "not a member of an allowed GitHub org or team"
    # Name the user in the audit trail if this identity is already linked.
    linked = (
        db.query(User)
        .filter(User.sso_issuer == settings.github_url, User.sso_subject == subject)
        .first()
    )
    raise SsoError("not_allowed", reason, user=linked)


def complete_login(
    db: Session, settings: Settings, *, cookie: str, code: str, state: str
) -> SsoSignIn:
    data = verify_state(FLOW, cookie, state)
    verifier = data.get("v")
    if not isinstance(verifier, str):
        raise SsoError("failed", "state cookie missing, invalid or expired")

    token, granted = _exchange_code(settings, code, verifier)
    orgs: dict[str, OrgState] = {}
    teams: set[str] = set()
    try:
        # Every read happens before the token is revoked; nothing after needs it.
        with http_client() as client:
            subject = _subject(client, settings, token)
            emails = _verified_emails(client, settings, token)
            if settings.github_needs_org_data:
                if ORG_SCOPE not in granted:
                    raise SsoError("failed", "GitHub did not grant the read:org scope")
                for org in settings.github_relevant_orgs:
                    orgs[org] = _org_state(client, settings, token, org)
                if settings.github_allowed_teams or settings.github_team_role_map:
                    teams = _user_teams(client, settings, token)
    finally:
        _revoke(settings, token)
    # A team counts only while the user is an active member of its org.
    teams = {team for team in teams if orgs.get(team.split("/")[0]) == "active"}
    if not emails:
        raise SsoError("not_linked", "GitHub account has no verified email")
    matched = _check_gate(db, settings, subject, orgs, teams) if settings.github_gated else None
    user, newly_linked = resolve_user(db, settings, settings.github_url, subject, emails)
    grants, unknown = desired_memberships(db, settings.github_team_role_map, teams)
    notes: dict = {}
    if matched:
        notes["matched"] = matched
    if unknown:
        notes["unknown_projects"] = unknown
    return SsoSignIn(user, newly_linked, source=SOURCE, grants=grants, notes=notes)
