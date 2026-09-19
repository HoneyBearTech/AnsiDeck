"""An in-process fake OpenID provider for the SSO tests.

It serves discovery, JWKS and a token endpoint through httpx.MockTransport, signs real
RS256 ID tokens, and enforces PKCE and client authentication itself, so a passing sign-in
proves the app's side of the flow is right. `forge` lets a test hand back a hostile token.
"""

import base64
import hashlib
import secrets
import time
from collections.abc import Callable
from urllib.parse import parse_qs, urlparse

import httpx
from joserfc import jwt
from joserfc.jwk import KeySet, RSAKey

ISSUER = "https://idp.test"
CLIENT_ID = "ansideck-client"
CLIENT_SECRET = "fake-client-secret"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class FakeOidc:
    def __init__(self) -> None:
        self.key = RSAKey.generate_key(2048, parameters={"kid": "k1", "use": "sig"})
        self.codes: dict[str, dict] = {}
        self.token_requests = 0
        # What discovery claims to support; None omits the field, like some providers do.
        self.advertised_algs: list[str] | None = ["RS256"]

    def metadata(self) -> dict:
        data = {
            "issuer": ISSUER,
            "authorization_endpoint": f"{ISSUER}/authorize",
            "token_endpoint": f"{ISSUER}/token",
            "jwks_uri": f"{ISSUER}/jwks",
            "id_token_signing_alg_values_supported": self.advertised_algs,
            "token_endpoint_auth_methods_supported": ["client_secret_basic"],
        }
        if self.advertised_algs is None:
            del data["id_token_signing_alg_values_supported"]
        return data

    def authorize(
        self,
        location: str,
        *,
        sub: str = "user-1",
        email: str | None = "alice@example.com",
        email_verified: object = True,
        claims: dict | None = None,
        drop: tuple[str, ...] = (),
        forge: Callable[[dict], str] | None = None,
    ) -> str:
        """Plays the user-approves step: reads the app's authorization request and returns
        the code the provider would redirect back with."""
        query = {k: v[0] for k, v in parse_qs(urlparse(location).query).items()}
        assert query["response_type"] == "code" and query["client_id"] == CLIENT_ID
        assert query["code_challenge_method"] == "S256"
        code = secrets.token_urlsafe(16)
        self.codes[code] = {
            "nonce": query["nonce"],
            "challenge": query["code_challenge"],
            "redirect_uri": query["redirect_uri"],
            "sub": sub,
            "email": email,
            "email_verified": email_verified,
            "claims": claims or {},
            "drop": drop,
            "forge": forge,
        }
        return code

    def sign(self, claims: dict, *, key: RSAKey | None = None) -> str:
        return jwt.encode({"alg": "RS256", "kid": "k1"}, claims, key or self.key)

    def _claims(self, entry: dict) -> dict:
        now = int(time.time())
        claims = {
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "sub": entry["sub"],
            "iat": now,
            "exp": now + 300,
            "nonce": entry["nonce"],
            "email": entry["email"],
            "email_verified": entry["email_verified"],
        }
        claims.update(entry["claims"])
        for name in entry["drop"]:
            claims.pop(name, None)
        return {k: v for k, v in claims.items() if v is not None}

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json=self.metadata())
        if path == "/jwks":
            return httpx.Response(200, json=KeySet([self.key]).as_dict(private=False))
        if path == "/token" and request.method == "POST":
            return self._token(request)
        return httpx.Response(404)

    def _token(self, request: httpx.Request) -> httpx.Response:
        self.token_requests += 1
        expected = "Basic " + base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
        if request.headers.get("authorization") != expected:
            return httpx.Response(401, json={"error": "invalid_client"})
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        entry = self.codes.pop(form.get("code", ""), None)  # single use
        if entry is None or form.get("grant_type") != "authorization_code":
            return httpx.Response(400, json={"error": "invalid_grant"})
        if form.get("redirect_uri") != entry["redirect_uri"]:
            return httpx.Response(400, json={"error": "invalid_grant"})
        verifier = form.get("code_verifier", "")
        if b64url(hashlib.sha256(verifier.encode()).digest()) != entry["challenge"]:
            return httpx.Response(400, json={"error": "invalid_grant", "why": "pkce"})
        claims = self._claims(entry)
        token = entry["forge"](claims) if entry["forge"] else self.sign(claims)
        return httpx.Response(
            200, json={"access_token": "at", "token_type": "Bearer", "id_token": token}
        )
