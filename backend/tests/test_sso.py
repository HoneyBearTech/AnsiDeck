import json
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastapi.testclient import TestClient
from joserfc import jwt
from joserfc.jwk import OctKey, RSAKey

from app import oidc
from app.config import Settings, get_settings
from app.db import get_sessionmaker
from app.main import app
from app.models import User
from tests.fake_oidc import CLIENT_ID, CLIENT_SECRET, ISSUER, FakeOidc, b64url
from tests.test_projects import _admin

PASSWORD = "a-long-test-password-1"


@pytest.fixture
def fake(monkeypatch) -> FakeOidc:
    # Runs before the `client` fixture (argument order), which then loads these settings.
    for name, value in {
        "PUBLIC_URL": "http://testserver",
        "OIDC_ISSUER": ISSUER,
        "OIDC_CLIENT_ID": CLIENT_ID,
        "OIDC_CLIENT_SECRET": CLIENT_SECRET,
        "OIDC_BUTTON_LABEL": "Acme SSO",
    }.items():
        monkeypatch.setenv(name, value)
    return FakeOidc()


@pytest.fixture
def sso(fake: FakeOidc, client: TestClient, monkeypatch):
    monkeypatch.setattr(
        oidc, "http_client", lambda: httpx.Client(transport=httpx.MockTransport(fake.handle))
    )
    oidc.clear_caches()
    admin = _admin(client)
    return fake, admin


def _provision(admin: TestClient, username: str, email: str | None, role: str = "operator") -> int:
    response = admin.post(
        "/api/users",
        json={"username": username, "password": PASSWORD, "role": role, "email": email},
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def _sign_in(fake: FakeOidc, browser: TestClient | None = None, **identity):
    browser = browser or TestClient(app)
    start = browser.get("/api/auth/oidc/login", follow_redirects=False)
    assert start.status_code == 302, start.text
    location = start.headers["location"]
    code = fake.authorize(location, **identity)
    state = parse_qs(urlparse(location).query)["state"][0]
    response = browser.get(
        "/api/auth/oidc/callback", params={"code": code, "state": state}, follow_redirects=False
    )
    return browser, response


def _ok(response) -> bool:
    return response.status_code == 302 and response.headers["location"] == "/"


def _refused(response, code: str) -> bool:
    return (
        response.status_code == 302
        and response.headers["location"] == f"/login?sso_error={code}"
        and "ansideck_session" not in response.headers.get("set-cookie", "")
    )


def _audit(admin: TestClient, action: str) -> list[dict]:
    return admin.get("/api/audit", params={"action": action, "limit": 100}).json()["items"]


# --------------------------------------------------------------------- configuration


def test_sso_is_off_by_default(client: TestClient) -> None:
    assert client.get("/api/auth/providers").json() == {"oidc": {"enabled": False, "label": "SSO"}}
    assert client.get("/api/auth/oidc/login", follow_redirects=False).status_code == 404
    assert client.get("/api/auth/oidc/callback", follow_redirects=False).status_code == 404


def test_providers_reports_the_button_label(sso) -> None:
    browser = TestClient(app)
    assert browser.get("/api/auth/providers").json() == {
        "oidc": {"enabled": True, "label": "Acme SSO"}
    }


def test_bad_oidc_configuration_refuses_to_start() -> None:
    base = {"oidc_issuer": "https://idp.test", "oidc_client_id": "c", "oidc_client_secret": "s"}
    with pytest.raises(ValueError, match="partially configured"):
        Settings(oidc_issuer="https://idp.test", oidc_client_id="c")
    with pytest.raises(ValueError, match="PUBLIC_URL"):
        Settings(**base)
    with pytest.raises(ValueError, match="requires https"):
        Settings(
            **base,
            public_url="http://ansideck.example.com",
            environment="production",
            auth_secret_key="a-real-secret-value",
            admin_password="a-real-admin-password",
        )
    assert Settings(**base, public_url="https://ansideck.example.com/").public_url == (
        "https://ansideck.example.com"
    )


# --------------------------------------------------------------------------- the flow


def test_login_redirects_to_the_provider_with_pkce_state_and_nonce(sso) -> None:
    browser = TestClient(app)
    response = browser.get("/api/auth/oidc/login", follow_redirects=False)
    assert response.status_code == 302
    url = urlparse(response.headers["location"])
    query = {k: v[0] for k, v in parse_qs(url.query).items()}
    assert f"{url.scheme}://{url.netloc}{url.path}" == f"{ISSUER}/authorize"
    assert query["response_type"] == "code" and query["client_id"] == CLIENT_ID
    assert query["redirect_uri"] == "http://testserver/api/auth/oidc/callback"
    assert query["scope"] == "openid email profile"
    assert query["code_challenge_method"] == "S256"
    assert len(query["state"]) >= 32 and len(query["nonce"]) >= 32
    cookie = response.headers["set-cookie"].lower()
    assert "ansideck_oidc=" in cookie and "httponly" in cookie and "samesite=lax" in cookie
    assert "path=/api/auth/oidc" in cookie


def test_a_preprovisioned_user_signs_in_and_is_linked(sso) -> None:
    fake, admin = sso
    _provision(admin, "alice", "Alice@Example.com")  # matched case-insensitively
    browser, response = _sign_in(fake, sub="idp-alice", email="alice@example.com")
    assert _ok(response)
    assert "ansideck_session=" in response.headers["set-cookie"]
    me = browser.get("/api/auth/me").json()
    assert me["username"] == "alice" and me["role"] == "operator"

    db = get_sessionmaker()()
    alice = db.query(User).filter(User.username == "alice").one()
    assert (alice.sso_issuer, alice.sso_subject) == (ISSUER, "idp-alice")
    db.close()
    assert len(_audit(admin, "auth.sso_link")) == 1
    login = _audit(admin, "auth.login")[0]
    assert login["actor_username"] == "alice" and login["detail"] == {"method": "sso"}


def test_later_sign_ins_match_the_bound_subject_not_the_email(sso) -> None:
    fake, admin = sso
    _provision(admin, "alice", "alice@example.com")
    assert _ok(_sign_in(fake, sub="idp-alice")[1])
    # Same person, email changed at the provider: still matched by subject.
    assert _ok(_sign_in(fake, sub="idp-alice", email="alice@newname.example")[1])
    # A different subject claiming the same email must NOT take over the linked account.
    assert _refused(_sign_in(fake, sub="idp-mallory", email="alice@example.com")[1], "not_linked")
    assert len(_audit(admin, "auth.sso_link")) == 1


def test_unknown_identities_get_nothing_and_no_account_is_created(sso) -> None:
    fake, admin = sso
    before = len(admin.get("/api/users").json())
    browser, response = _sign_in(fake, sub="stranger", email="nobody@example.com")
    assert _refused(response, "not_linked")
    assert browser.get("/api/auth/me").status_code == 401
    assert len(admin.get("/api/users").json()) == before
    failure = _audit(admin, "auth.sso")[0]
    assert failure["outcome"] == "failure" and failure["detail"]["email"] == "nobody@example.com"


@pytest.mark.parametrize("verified", [False, "true", None])
def test_only_a_verified_email_counts(sso, verified) -> None:
    fake, admin = sso
    _provision(admin, "alice", "alice@example.com")
    assert _refused(_sign_in(fake, email_verified=verified)[1], "not_linked")


def test_a_missing_email_claim_is_refused(sso) -> None:
    fake, admin = sso
    _provision(admin, "alice", "alice@example.com")
    assert _refused(_sign_in(fake, email=None)[1], "failed")


def _none_alg(claims: dict) -> str:
    header = b64url(json.dumps({"alg": "none", "kid": "k1"}).encode())
    return f"{header}.{b64url(json.dumps(claims).encode())}."


@pytest.mark.parametrize(
    "case",
    ["aud", "iss", "expired", "nonce", "no_sub", "none_alg", "hs256_confusion", "wrong_key"],
)
def test_hostile_id_tokens_are_refused(sso, case) -> None:
    fake, admin = sso
    _provision(admin, "alice", "alice@example.com")
    now = 1_000_000_000
    kwargs: dict = {
        "aud": {"claims": {"aud": "someone-else"}},
        "iss": {"claims": {"iss": "https://evil.example"}},
        "expired": {"claims": {"exp": now}},
        "nonce": {"claims": {"nonce": "not-the-one-we-sent"}},
        "no_sub": {"drop": ("sub",)},
        "none_alg": {"forge": _none_alg},
        "hs256_confusion": {
            "forge": lambda c: jwt.encode(
                {"alg": "HS256", "kid": "k1"}, c, OctKey.import_key(fake.key.as_pem(private=False))
            )
        },
        "wrong_key": {
            "forge": lambda c: fake.sign(c, key=RSAKey.generate_key(2048, parameters={"kid": "k1"}))
        },
    }[case]
    browser, response = _sign_in(fake, **kwargs)
    assert _refused(response, "failed"), case
    assert browser.get("/api/auth/me").status_code == 401
    db = get_sessionmaker()()
    assert db.query(User).filter(User.sso_subject.isnot(None)).count() == 0  # nothing linked
    db.close()


@pytest.mark.parametrize("advertised", [None, ["HS256", "RS256"]])
def test_the_algorithm_allowlist_holds_whatever_the_provider_advertises(sso, advertised) -> None:
    """Key confusion must fail whatever discovery advertises or omits. (joserfc also rejects
    HS256 against an RSA key on its own, so this pins behaviour rather than one layer.)"""
    fake, admin = sso
    fake.advertised_algs = advertised
    _provision(admin, "alice", "alice@example.com")
    forge = lambda c: jwt.encode(  # noqa: E731
        {"alg": "HS256", "kid": "k1"}, c, OctKey.import_key(fake.key.as_pem(private=False))
    )
    assert _refused(_sign_in(fake, forge=forge)[1], "failed")
    assert _ok(_sign_in(fake)[1])  # honest RS256 tokens still work


def test_several_audiences_need_our_client_as_azp(sso) -> None:
    fake, admin = sso
    _provision(admin, "alice", "alice@example.com")
    both = {"aud": [CLIENT_ID, "other-api"]}
    assert _refused(_sign_in(fake, claims=both)[1], "failed")
    assert _ok(_sign_in(fake, claims={**both, "azp": CLIENT_ID})[1])


def test_state_is_enforced(sso) -> None:
    fake, admin = sso
    _provision(admin, "alice", "alice@example.com")
    browser = TestClient(app)
    location = browser.get("/api/auth/oidc/login", follow_redirects=False).headers["location"]
    code = fake.authorize(location)
    callback = "/api/auth/oidc/callback"
    # wrong state
    assert _refused(
        browser.get(callback, params={"code": code, "state": "forged"}, follow_redirects=False),
        "failed",
    )
    # no cookie at all (a login-CSRF attempt from another browser)
    state = parse_qs(urlparse(location).query)["state"][0]
    other = TestClient(app)
    assert _refused(
        other.get(callback, params={"code": code, "state": state}, follow_redirects=False), "failed"
    )
    # tampered cookie
    browser.cookies.set("ansideck_oidc", "garbage", path="/api/auth/oidc")
    assert _refused(
        browser.get(callback, params={"code": code, "state": state}, follow_redirects=False),
        "failed",
    )
    assert fake.token_requests == 0  # never even reached the provider


def test_the_state_cookie_expires_and_cannot_be_replayed(sso, monkeypatch) -> None:
    fake, admin = sso
    _provision(admin, "alice", "alice@example.com")
    browser, response = _sign_in(fake)
    assert _ok(response)
    # The successful callback consumed the cookie: replaying the same request fails.
    assert _refused(
        browser.get(
            "/api/auth/oidc/callback", params={"code": "x", "state": "y"}, follow_redirects=False
        ),
        "failed",
    )

    monkeypatch.setattr(oidc, "STATE_MAX_AGE_SECONDS", -1)
    assert _refused(_sign_in(fake)[1], "failed")


def test_the_redirect_target_is_never_user_controlled(sso) -> None:
    fake, admin = sso
    _provision(admin, "alice", "alice@example.com")
    browser = TestClient(app)
    location = browser.get(
        "/api/auth/oidc/login?next=https://evil.example", follow_redirects=False
    ).headers["location"]
    code = fake.authorize(location)
    state = parse_qs(urlparse(location).query)["state"][0]
    response = browser.get(
        "/api/auth/oidc/callback",
        params={
            "code": code,
            "state": state,
            "next": "https://evil.example",
            "redirect_uri": "https://evil.example",
        },
        follow_redirects=False,
    )
    assert response.headers["location"] == "/"
    # a provider-reported error is also just a generic failure
    assert _refused(
        browser.get(
            "/api/auth/oidc/callback", params={"error": "access_denied"}, follow_redirects=False
        ),
        "failed",
    )


# ------------------------------------------------------------------- who may use SSO


def test_global_admins_cannot_use_sso_unless_allowed(sso, monkeypatch) -> None:
    fake, admin = sso
    _provision(admin, "root2", "root2@example.com", role="admin")
    assert _refused(_sign_in(fake, sub="idp-root2", email="root2@example.com")[1], "not_linked")
    reasons = [e["detail"]["reason"] for e in _audit(admin, "auth.sso")]
    assert any("global admins" in r for r in reasons)

    monkeypatch.setenv("OIDC_ALLOW_ADMIN", "true")
    get_settings.cache_clear()
    browser, response = _sign_in(fake, sub="idp-root2", email="root2@example.com")
    assert _ok(response) and browser.get("/api/auth/me").json()["role"] == "admin"


def test_deactivated_users_cannot_sign_in(sso) -> None:
    fake, admin = sso
    uid = _provision(admin, "alice", "alice@example.com")
    assert _ok(_sign_in(fake, sub="idp-alice")[1])
    assert admin.patch(f"/api/users/{uid}", json={"is_active": False}).status_code == 200
    assert _refused(_sign_in(fake, sub="idp-alice")[1], "not_linked")


def test_email_domain_allowlist(sso, monkeypatch) -> None:
    fake, admin = sso
    monkeypatch.setenv("OIDC_ALLOWED_EMAIL_DOMAINS", '["corp.example"]')
    get_settings.cache_clear()
    _provision(admin, "alice", "alice@example.com")
    _provision(admin, "bob", "bob@corp.example")
    assert _refused(_sign_in(fake, sub="a", email="alice@example.com")[1], "not_linked")
    assert _ok(_sign_in(fake, sub="b", email="bob@corp.example")[1])


def test_repeated_failures_are_throttled_before_reaching_the_provider(sso) -> None:
    fake, admin = sso
    _provision(admin, "alice", "alice@example.com")
    browser = TestClient(app)
    for _ in range(20):
        browser.get("/api/auth/oidc/callback", follow_redirects=False)
    # Blocked at the door: even starting a new sign-in is refused, and the provider is never called.
    assert _refused(browser.get("/api/auth/oidc/login", follow_redirects=False), "failed")
    assert fake.token_requests == 0


# --------------------------------------------------------------------- admin surface


def test_user_email_and_unlink_management(sso) -> None:
    fake, admin = sso
    uid = _provision(admin, "alice", "alice@example.com")
    dup = admin.post(
        "/api/users",
        json={"username": "alice2", "password": PASSWORD, "email": "ALICE@example.com"},
    )
    assert dup.status_code == 409

    assert _ok(_sign_in(fake, sub="idp-alice")[1])
    shown = next(u for u in admin.get("/api/users").json() if u["id"] == uid)
    assert shown["email"] == "alice@example.com" and shown["sso_linked"] is True

    assert admin.delete(f"/api/users/{uid}/sso-link").status_code == 204
    assert next(u for u in admin.get("/api/users").json() if u["id"] == uid)["sso_linked"] is False
    assert len(_audit(admin, "user.sso_unlink")) == 1
    # unlinked, so a new provider account with the same verified email can link again
    assert _ok(_sign_in(fake, sub="idp-alice-new")[1])

    assert admin.patch(f"/api/users/{uid}", json={"email": None}).json()["email"] is None
    assert (
        admin.patch(f"/api/users/{uid}", json={"is_active": True}).status_code == 200
    )  # email untouched


def test_audit_never_holds_codes_tokens_or_secrets(sso) -> None:
    fake, admin = sso
    _provision(admin, "alice", "alice@example.com")
    _sign_in(fake, sub="idp-alice")
    _sign_in(fake, sub="stranger", email="nobody@example.com")
    dump = json.dumps(admin.get("/api/audit", params={"limit": 200}).json())
    assert CLIENT_SECRET not in dump and "id_token" not in dump and "code_verifier" not in dump
