"""An in-process fake GitHub for the GitHub sign-in tests.

It serves the token endpoint and the REST API through httpx.MockTransport and enforces the
parts of the protocol the app must get right: client authentication, PKCE, single-use
codes, bearer tokens, and token revocation. Like the real thing it answers a bad or
expired code with HTTP 200 and an `error` in the body. Knobs on the instance let a test
simulate an outage, a missing scope, or a failing revocation.
"""

import base64
import hashlib
import json
import secrets
from urllib.parse import parse_qs, urlparse

import httpx

GITHUB_URL = "https://github.test"
API_URL = "https://api.github.test"
CLIENT_ID = "ansideck-gh-client"
CLIENT_SECRET = "fake-gh-client-secret"


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

    def authorize(
        self,
        location: str,
        *,
        id: int | object = 1001,
        login: str = "alice-gh",
        emails: list[dict] | None = None,
    ) -> str:
        """Plays the user-approves step: reads the app's authorization request and returns
        the code GitHub would redirect back with."""
        url = urlparse(location)
        assert f"{url.scheme}://{url.netloc}{url.path}" == f"{GITHUB_URL}/login/oauth/authorize"
        query = {k: v[0] for k, v in parse_qs(url.query).items()}
        assert query["client_id"] == CLIENT_ID
        assert query["code_challenge_method"] == "S256"
        assert query["scope"] == "read:user user:email"
        assert query["allow_signup"] == "false"
        code = secrets.token_urlsafe(16)
        self.codes[code] = {
            "challenge": query["code_challenge"],
            "redirect_uri": query["redirect_uri"],
            "identity": {
                "id": id,
                "login": login,
                "emails": _default_emails() if emails is None else emails,
            },
        }
        return code

    def handle(self, request: httpx.Request) -> httpx.Response:
        url = request.url
        base = f"{url.scheme}://{url.host}"
        if base == GITHUB_URL and url.path == "/login/oauth/access_token":
            return self._token(request)
        if base == API_URL:
            if request.method == "GET" and url.path == "/user":
                return self._user(request)
            if request.method == "GET" and url.path == "/user/emails":
                return self._emails(request)
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
        self.tokens[token] = entry["identity"]
        self.issued.append(token)
        return httpx.Response(
            200,
            json={"access_token": token, "token_type": "bearer", "scope": "read:user,user:email"},
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

    def _revoke(self, request: httpx.Request) -> httpx.Response:
        if self.revoke_raises:
            raise httpx.ConnectError("revocation endpoint unreachable", request=request)
        expected = "Basic " + base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
        if request.headers.get("authorization") != expected:
            return httpx.Response(401, json={"message": "Bad credentials"})
        if self.revoke_status == 204:
            self.revoked.append(json.loads(request.content)["access_token"])
        return httpx.Response(self.revoke_status)
