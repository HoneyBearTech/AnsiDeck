"""An in-process fake GitHub for the GitHub sign-in tests.

It serves the token endpoint and the REST API through httpx.MockTransport and enforces the
parts of the protocol the app must get right: client authentication, PKCE, single-use
codes, bearer tokens, and token revocation. Like the real thing it answers a bad or
expired code with HTTP 200 and an `error` in the body. Knobs on the instance let a test
simulate an outage, a missing scope, or a failing revocation.

Org memberships and teams (read:org) follow GitHub's REST docs: GET /user/memberships/orgs/{org}
answers 200 with `state` active/pending or 404, and 403 with an "OAuth App access restrictions"
message for an org that hasn't approved the app; GET /user/teams pages by `per_page`/`page`
(at most 100) and leaves such orgs' teams out. Its Link header points elsewhere on purpose: the
app must never follow it.
"""

import base64
import hashlib
import json
import secrets
from urllib.parse import parse_qs, unquote, urlparse

import httpx

GITHUB_URL = "https://github.test"
API_URL = "https://api.github.test"
CLIENT_ID = "ansideck-gh-client"
CLIENT_SECRET = "fake-gh-client-secret"
BASE_SCOPE = "read:user user:email"
ORG_SCOPE = f"{BASE_SCOPE} read:org"
LINK_HOST = "https://link.elsewhere.test"


def _default_emails() -> list[dict]:
    return [{"email": "alice@example.com", "verified": True, "primary": True}]


class FakeGithub:
    def __init__(self) -> None:
        self.codes: dict[str, dict] = {}
        self.tokens: dict[str, dict] = {}  # access token -> identity
        self.issued: list[str] = []  # every token ever handed out
        self.revoked: list[str] = []
        self.token_requests = 0
        # Failure knobs.
        self.token_error: str | None = None  # 200 + {"error": ...}, GitHub-style
        self.token_status = 200  # any other status simulates an outage
        self.user_status = 200
        self.emails_status = 200  # e.g. 404/403 when the `user:email` scope was not granted
        self.revoke_status = 204
        self.revoke_raises = False
        self.expected_scope = BASE_SCOPE  # what the authorization request must ask for
        self.restricted_orgs: set[str] = set()  # orgs that haven't approved the OAuth app
        self.memberships_status = 200
        self.teams_status = 200
        self.teams_body: object = None  # replaces the /user/teams page when set
        self.rate_limited = False
        self.requests: list[tuple[str, str, str, dict]] = []  # (method, host, path, query)

    def authorize(
        self,
        location: str,
        *,
        id: int | object = 1001,
        login: str = "alice-gh",
        emails: list[dict] | None = None,
        orgs: dict[str, str] | None = None,
        teams: list[tuple[str, str]] | None = None,
        granted_scope: str | None = None,
    ) -> str:
        """Plays the user-approves step: reads the app's authorization request and returns
        the code GitHub would redirect back with."""
        url = urlparse(location)
        assert f"{url.scheme}://{url.netloc}{url.path}" == f"{GITHUB_URL}/login/oauth/authorize"
        query = {k: v[0] for k, v in parse_qs(url.query).items()}
        assert query["client_id"] == CLIENT_ID
        assert query["code_challenge_method"] == "S256"
        assert query["scope"] == self.expected_scope
        assert query["allow_signup"] == "false"
        code = secrets.token_urlsafe(16)
        self.codes[code] = {
            "challenge": query["code_challenge"],
            "redirect_uri": query["redirect_uri"],
            # What the user let through on the consent screen (they can untick a scope).
            "scope": ",".join(query["scope"].split()) if granted_scope is None else granted_scope,
            "identity": {
                "id": id,
                "login": login,
                "emails": _default_emails() if emails is None else emails,
                "orgs": orgs or {},  # org login (GitHub's capitalisation) -> active / pending
                "teams": teams or [],  # (org login, team slug)
            },
        }
        return code

    def handle(self, request: httpx.Request) -> httpx.Response:
        url = request.url
        base = f"{url.scheme}://{url.host}"
        self.requests.append((request.method, base, url.path, dict(url.params)))
        if base == GITHUB_URL and url.path == "/login/oauth/access_token":
            return self._token(request)
        if base == API_URL:
            if request.method == "GET" and url.path == "/user":
                return self._user(request)
            if request.method == "GET" and url.path == "/user/emails":
                return self._emails(request)
            if request.method == "GET" and url.path.startswith("/user/memberships/orgs/"):
                return self._membership(request, unquote(url.path.rsplit("/", 1)[1]))
            if request.method == "GET" and url.path == "/user/teams":
                return self._teams(request)
            if request.method == "DELETE" and url.path == f"/applications/{CLIENT_ID}/token":
                return self._revoke(request)
        return httpx.Response(404, json={"message": "Not Found"})

    def _token(self, request: httpx.Request) -> httpx.Response:
        self.token_requests += 1
        if self.token_status != 200:
            return httpx.Response(self.token_status, text="upstream trouble")
        if self.token_error:
            return httpx.Response(200, json={"error": self.token_error})
        assert request.headers["accept"] == "application/json"
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        entry = self.codes.pop(form.get("code", ""), None)  # single use
        if form.get("client_id") != CLIENT_ID or form.get("client_secret") != CLIENT_SECRET:
            return httpx.Response(200, json={"error": "incorrect_client_credentials"})
        if entry is None:
            return httpx.Response(200, json={"error": "bad_verification_code"})
        verifier = form.get("code_verifier", "")
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        if challenge.rstrip(b"=").decode() != entry["challenge"]:
            return httpx.Response(200, json={"error": "bad_verification_code"})
        if form.get("redirect_uri") != entry["redirect_uri"]:
            return httpx.Response(200, json={"error": "redirect_uri_mismatch"})
        token = "gho_" + secrets.token_urlsafe(24)
        self.tokens[token] = {**entry["identity"], "scope": entry["scope"]}
        self.issued.append(token)
        return httpx.Response(
            200, json={"access_token": token, "token_type": "bearer", "scope": entry["scope"]}
        )

    def _identity(self, request: httpx.Request) -> dict | None:
        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() != "bearer" or token in self.revoked:
            return None
        return self.tokens.get(token)

    def _user(self, request: httpx.Request) -> httpx.Response:
        if self.user_status != 200:
            return httpx.Response(self.user_status, json={"message": "nope"})
        identity = self._identity(request)
        if identity is None:
            return httpx.Response(401, json={"message": "Bad credentials"})
        return httpx.Response(200, json={"id": identity["id"], "login": identity["login"]})

    def _emails(self, request: httpx.Request) -> httpx.Response:
        if self.emails_status != 200:
            return httpx.Response(self.emails_status, json={"message": "nope"})
        identity = self._identity(request)
        if identity is None:
            return httpx.Response(401, json={"message": "Bad credentials"})
        return httpx.Response(200, json=identity["emails"])

    def _org_identity(self, request: httpx.Request) -> tuple[dict | None, httpx.Response | None]:
        identity = self._identity(request)
        if identity is None:
            return None, httpx.Response(401, json={"message": "Bad credentials"})
        if self.rate_limited:
            return None, httpx.Response(
                403,
                headers={"x-ratelimit-remaining": "0"},
                json={"message": "API rate limit exceeded"},
            )
        if "read:org" not in identity["scope"].split(","):
            return None, httpx.Response(403, json={"message": "Resource not accessible"})
        return identity, None

    def _restricted(self, org: str) -> bool:
        return org.lower() in {o.lower() for o in self.restricted_orgs}

    def _membership(self, request: httpx.Request, org: str) -> httpx.Response:
        if self.memberships_status != 200:
            return httpx.Response(self.memberships_status, json={"message": "nope"})
        identity, refusal = self._org_identity(request)
        if refusal is not None:
            return refusal
        assert identity is not None
        if self._restricted(org):
            return httpx.Response(
                403,
                json={
                    "message": "Although you appear to have the correct authorization "
                    f"credentials, the `{org}` organization has enabled OAuth App access "
                    "restrictions, meaning that data access to third-parties is limited."
                },
            )
        for login, state in identity["orgs"].items():
            if login.lower() == org.lower():
                return httpx.Response(
                    200,
                    json={"state": state, "role": "member", "organization": {"login": login}},
                )
        return httpx.Response(404, json={"message": "Not Found"})

    def _teams(self, request: httpx.Request) -> httpx.Response:
        if self.teams_status != 200:
            return httpx.Response(self.teams_status, json={"message": "nope"})
        identity, refusal = self._org_identity(request)
        if refusal is not None:
            return refusal
        assert identity is not None
        per_page = min(int(request.url.params.get("per_page", "30")), 100)
        page = int(request.url.params.get("page", "1"))
        visible = [
            {"slug": slug, "name": slug.title(), "organization": {"login": org}}
            for org, slug in identity["teams"]
            if not self._restricted(org)
        ]
        chunk = visible[(page - 1) * per_page : page * per_page]
        if self.teams_body is not None:
            return httpx.Response(200, json=self.teams_body)
        link = f'<{LINK_HOST}/user/teams?page={page + 1}>; rel="next"'
        return httpx.Response(200, json=chunk, headers={"link": link})

    def _revoke(self, request: httpx.Request) -> httpx.Response:
        if self.revoke_raises:
            raise httpx.ConnectError("revocation endpoint unreachable", request=request)
        expected = "Basic " + base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
        if request.headers.get("authorization") != expected:
            return httpx.Response(401, json={"message": "Bad credentials"})
        if self.revoke_status == 204:
            self.revoked.append(json.loads(request.content)["access_token"])
        return httpx.Response(self.revoke_status)
