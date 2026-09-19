import json
import logging
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastapi.testclient import TestClient

from app import github_login, oidc, sso_common
from app.config import Settings, get_settings
from app.db import get_sessionmaker
from app.main import app
from app.models import User
from tests.fake_github import API_URL, CLIENT_ID, CLIENT_SECRET, GITHUB_URL, FakeGithub
from tests.fake_oidc import FakeOidc
from tests.test_projects import _admin
from tests.test_sso import _audit, _ok, _provision, _refused

CALLBACK = "/api/auth/github/callback"


def _verified(email: str, *, primary: bool = False) -> dict:
    return {"email": email, "verified": True, "primary": primary}


@pytest.fixture
def fake(monkeypatch) -> FakeGithub:
    # Runs before the `client` fixture (argument order), which then loads these settings.
    for name, value in {
        "PUBLIC_URL": "http://testserver",
        "GITHUB_CLIENT_ID": CLIENT_ID,
        "GITHUB_CLIENT_SECRET": CLIENT_SECRET,
        "GITHUB_URL": GITHUB_URL,
        "GITHUB_API_URL": API_URL,
        "GITHUB_BUTTON_LABEL": "Acme GitHub",
    }.items():
        monkeypatch.setenv(name, value)
    return FakeGithub()


@pytest.fixture
def gh(fake: FakeGithub, client: TestClient, monkeypatch):
    monkeypatch.setattr(
        github_login,
        "http_client",
        lambda: httpx.Client(transport=httpx.MockTransport(fake.handle)),
    )
    return fake, _admin(client)


def _sign_in(fake: FakeGithub, browser: TestClient | None = None, **identity):
    browser = browser or TestClient(app)
    start = browser.get("/api/auth/github/login", follow_redirects=False)
    assert start.status_code == 302, start.text
    location = start.headers["location"]
    code = fake.authorize(location, **identity)
    state = parse_qs(urlparse(location).query)["state"][0]
    response = browser.get(CALLBACK, params={"code": code, "state": state}, follow_redirects=False)
    return browser, response


def _reasons(admin: TestClient) -> list[str]:
    return [e["detail"]["reason"] for e in _audit(admin, "auth.sso")]


def _user_row(username: str) -> User:
    db = get_sessionmaker()()
    try:
        return db.query(User).filter(User.username == username).one()
    finally:
        db.close()


# --------------------------------------------------------------------- configuration


def test_github_is_off_by_default(client: TestClient) -> None:
    assert client.get("/api/auth/providers").json()["github"] == {
        "enabled": False,
        "label": "GitHub",
    }
    assert client.get("/api/auth/github/login", follow_redirects=False).status_code == 404
    assert client.get(CALLBACK, follow_redirects=False).status_code == 404


def test_providers_reports_the_button_label(gh) -> None:
    body = TestClient(app).get("/api/auth/providers").json()
    assert body["github"] == {"enabled": True, "label": "Acme GitHub"}
    assert body["oidc"]["enabled"] is False


def test_bad_github_configuration_refuses_to_start() -> None:
    with pytest.raises(ValueError, match="partially configured"):
        Settings(github_client_id="c")
    with pytest.raises(ValueError, match="partially configured"):
        Settings(github_client_secret="s")
    with pytest.raises(ValueError, match="PUBLIC_URL"):
        Settings(github_client_id="c", github_client_secret="s")
    base = {"github_client_id": "c", "github_client_secret": "s"}
    production = {
        "environment": "production",
        "auth_secret_key": "a-real-secret-value",
        "admin_password": "a-real-admin-password",
    }
    with pytest.raises(ValueError, match="requires https"):
        Settings(**base, **production, public_url="http://ansideck.example.com")
    with pytest.raises(ValueError, match="requires https"):
        Settings(
            **base, **production, public_url="https://ansideck.example.com", github_url="http://gh"
        )
    settings = Settings(
        **base, public_url="https://ansideck.example.com/", github_url="https://gh/"
    )
    assert (settings.public_url, settings.github_url) == (
        "https://ansideck.example.com",
        "https://gh",
    )


def test_the_shared_sso_knobs_keep_their_original_oidc_names(monkeypatch) -> None:
    monkeypatch.setenv("OIDC_ALLOW_ADMIN", "true")
    monkeypatch.setenv("OIDC_ALLOWED_EMAIL_DOMAINS", '["old.example"]')
    settings = Settings()
    assert settings.sso_allow_admin is True and settings.sso_allowed_email_domains == [
        "old.example"
    ]
    monkeypatch.setenv("SSO_ALLOW_ADMIN", "false")
    assert Settings().sso_allow_admin is False  # the new name wins


# --------------------------------------------------------------------------- the flow


def test_login_redirects_to_github_with_pkce_and_state(gh) -> None:
    response = TestClient(app).get("/api/auth/github/login", follow_redirects=False)
    assert response.status_code == 302
    url = urlparse(response.headers["location"])
    query = {k: v[0] for k, v in parse_qs(url.query).items()}
    assert f"{url.scheme}://{url.netloc}{url.path}" == f"{GITHUB_URL}/login/oauth/authorize"
    assert query["client_id"] == CLIENT_ID
    assert query["redirect_uri"] == "http://testserver/api/auth/github/callback"
    assert query["scope"] == "read:user user:email"
    assert query["allow_signup"] == "false"
    assert query["code_challenge_method"] == "S256" and len(query["state"]) >= 32
    cookie = response.headers["set-cookie"].lower()
    assert "ansideck_gh=" in cookie and "httponly" in cookie and "samesite=lax" in cookie
    assert "path=/api/auth/github" in cookie
    assert CLIENT_SECRET not in response.headers["location"]


def test_a_preprovisioned_user_signs_in_and_is_linked(gh) -> None:
    fake, admin = gh
    _provision(admin, "alice", "Alice@Example.com")  # matched case-insensitively
    browser, response = _sign_in(fake, id=1001)
    assert _ok(response)
    assert "ansideck_session=" in response.headers["set-cookie"]
    me = browser.get("/api/auth/me").json()
    assert me["username"] == "alice" and me["role"] == "operator"

    alice = _user_row("alice")
    assert (alice.sso_issuer, alice.sso_subject) == (GITHUB_URL, "1001")
    assert len(_audit(admin, "auth.sso_link")) == 1
    login = _audit(admin, "auth.login")[0]
    assert login["actor_username"] == "alice" and login["detail"] == {"method": "github"}
    # The token was used for two reads and then revoked.
    assert fake.revoked == fake.issued and len(fake.issued) == 1


def test_later_sign_ins_match_the_numeric_id_not_the_login_or_email(gh) -> None:
    fake, admin = gh
    _provision(admin, "alice", "alice@example.com")
    assert _ok(_sign_in(fake, id=1001, login="alice-gh")[1])
    # Renamed on GitHub, and the email changed: still the same person, matched by id.
    renamed = [_verified("alice@newname.example", primary=True)]
    assert _ok(_sign_in(fake, id=1001, login="alice-renamed", emails=renamed)[1])
    # Someone else who was handed the old login, or who claims the same email, gets nothing.
    assert _refused(_sign_in(fake, id=2002, login="alice-gh")[1], "not_linked")
    assert len(_audit(admin, "auth.sso_link")) == 1


def test_unknown_identities_get_nothing_and_no_account_is_created(gh) -> None:
    fake, admin = gh
    before = len(admin.get("/api/users").json())
    browser, response = _sign_in(fake, id=3003, emails=[_verified("nobody@example.com")])
    assert _refused(response, "not_linked")
    assert browser.get("/api/auth/me").status_code == 401
    assert len(admin.get("/api/users").json()) == before
    failure = _audit(admin, "auth.sso")[0]
    assert failure["outcome"] == "failure" and failure["detail"]["email"] == "nobody@example.com"


def test_unverified_emails_are_ignored(gh) -> None:
    fake, admin = gh
    _provision(admin, "alice", "alice@example.com")
    unverified = [{"email": "alice@example.com", "verified": False, "primary": True}]
    browser, response = _sign_in(fake, id=6666, emails=unverified)
    assert _refused(response, "not_linked")
    assert "no verified email" in _reasons(admin)[0]
    assert _user_row("alice").sso_subject is None
    # Anything that isn't literally `true` is unverified too.
    truthy = [{"email": "alice@example.com", "verified": "true", "primary": True}]
    assert _refused(_sign_in(fake, id=6666, emails=truthy)[1], "not_linked")


def test_an_account_with_no_verified_email_at_all_is_refused(gh) -> None:
    fake, admin = gh
    _provision(admin, "alice", "alice@example.com")
    assert _refused(_sign_in(fake, id=1001, emails=[])[1], "not_linked")
    assert _ok(_sign_in(fake, id=1001)[1])  # ...and nothing was half-linked by the refusal
    assert _refused(_sign_in(fake, id=1001, emails=[])[1], "not_linked")  # even once linked


def test_any_verified_email_may_link_and_noreply_addresses_are_harmless(gh) -> None:
    fake, admin = gh
    _provision(admin, "alice", "alice@example.com")
    emails = [
        _verified("1001+alice-gh@users.noreply.github.com"),
        {"email": "alice@other.example", "verified": False, "primary": False},
        _verified("alice@example.com"),
    ]
    assert _ok(_sign_in(fake, id=1001, emails=emails)[1])
    assert _user_row("alice").sso_subject == "1001"


def test_a_sign_in_matching_two_accounts_is_refused_not_guessed(gh) -> None:
    fake, admin = gh
    _provision(admin, "alice", "alice@example.com")
    _provision(admin, "alice-work", "alice@work.example")
    both = [_verified("alice@example.com"), _verified("alice@work.example")]
    assert _refused(_sign_in(fake, id=1001, emails=both)[1], "not_linked")
    assert "more than one account" in _reasons(admin)[0]
    assert _user_row("alice").sso_subject is None and _user_row("alice-work").sso_subject is None


def test_one_identity_per_user(gh) -> None:
    fake, admin = gh
    uid = _provision(admin, "alice", "alice@example.com")
    # Already bound to some other provider identity: GitHub can't also link, until unlinked.
    db = get_sessionmaker()()
    db.query(User).filter(User.id == uid).update(
        {"sso_issuer": "https://idp.test", "sso_subject": "idp-alice"}
    )
    db.commit()
    db.close()
    assert _refused(_sign_in(fake, id=1001)[1], "not_linked")
    assert admin.delete(f"/api/users/{uid}/sso-link").status_code == 204
    assert _ok(_sign_in(fake, id=1001)[1])


# ------------------------------------------------------------------- who may use it


def test_global_admins_cannot_use_github_unless_allowed(gh, monkeypatch) -> None:
    fake, admin = gh
    _provision(admin, "root2", "root2@example.com", role="admin")
    emails = [_verified("root2@example.com")]
    assert _refused(_sign_in(fake, id=42, emails=emails)[1], "not_linked")
    assert any("global admins" in r for r in _reasons(admin))

    monkeypatch.setenv("SSO_ALLOW_ADMIN", "true")
    get_settings.cache_clear()
    browser, response = _sign_in(fake, id=42, emails=emails)
    assert _ok(response) and browser.get("/api/auth/me").json()["role"] == "admin"


def test_deactivated_users_cannot_sign_in(gh) -> None:
    fake, admin = gh
    uid = _provision(admin, "alice", "alice@example.com")
    assert _ok(_sign_in(fake, id=1001)[1])
    assert admin.patch(f"/api/users/{uid}", json={"is_active": False}).status_code == 200
    assert _refused(_sign_in(fake, id=1001)[1], "not_linked")


def test_email_domain_allowlist(gh, monkeypatch) -> None:
    fake, admin = gh
    monkeypatch.setenv("SSO_ALLOWED_EMAIL_DOMAINS", '["corp.example"]')
    get_settings.cache_clear()
    _provision(admin, "alice", "alice@example.com")
    _provision(admin, "bob", "bob@corp.example")
    assert _refused(_sign_in(fake, id=1, emails=[_verified("alice@example.com")])[1], "not_linked")
    both = [_verified("alice@example.com"), _verified("bob@corp.example")]
    assert _ok(_sign_in(fake, id=2, emails=both)[1])  # only the allowed address counts
    assert _user_row("bob").sso_subject == "2" and _user_row("alice").sso_subject is None


# ---------------------------------------------------------------------- state / abuse


def test_state_is_enforced(gh) -> None:
    fake, admin = gh
    _provision(admin, "alice", "alice@example.com")

    def begin(browser: TestClient):
        location = browser.get("/api/auth/github/login", follow_redirects=False).headers["location"]
        return fake.authorize(location), parse_qs(urlparse(location).query)["state"][0]

    browser = TestClient(app)
    code, _ = begin(browser)
    assert _refused(
        browser.get(CALLBACK, params={"code": code, "state": "wrong"}, follow_redirects=False),
        "failed",
    )
    # No state cookie at all (e.g. the callback opened in another browser).
    code, state = begin(TestClient(app))
    assert _refused(
        TestClient(app).get(
            CALLBACK, params={"code": code, "state": state}, follow_redirects=False
        ),
        "failed",
    )
    # A tampered cookie.
    browser = TestClient(app)
    code, state = begin(browser)
    browser.cookies.set("ansideck_gh", browser.cookies["ansideck_gh"][:-2] + "xx", path="/")
    assert _refused(
        browser.get(CALLBACK, params={"code": code, "state": state}, follow_redirects=False),
        "failed",
    )
    assert fake.token_requests == 0  # none of it ever reached GitHub


def test_a_state_cookie_from_another_flow_is_not_accepted(gh) -> None:
    fake, admin = gh
    _provision(admin, "alice", "alice@example.com")
    browser = TestClient(app)
    location = browser.get("/api/auth/github/login", follow_redirects=False).headers["location"]
    code = fake.authorize(location)
    # Signed with the app's key but for the OIDC flow (different salt).
    browser.cookies.set("ansideck_gh", sso_common.sign_state("oidc", {"s": "s", "v": "v"}))
    assert _refused(
        browser.get(CALLBACK, params={"code": code, "state": "s"}, follow_redirects=False), "failed"
    )
    assert fake.token_requests == 0


def test_the_state_cookie_expires_and_cannot_be_replayed(gh, monkeypatch) -> None:
    fake, admin = gh
    _provision(admin, "alice", "alice@example.com")
    browser, response = _sign_in(fake)
    assert _ok(response)
    # The successful callback consumed the cookie: replaying the same request fails.
    assert _refused(
        browser.get(CALLBACK, params={"code": "x", "state": "y"}, follow_redirects=False), "failed"
    )
    monkeypatch.setattr(sso_common, "STATE_MAX_AGE_SECONDS", -1)
    assert _refused(_sign_in(fake)[1], "failed")


def test_the_authorization_code_is_single_use(gh) -> None:
    fake, admin = gh
    _provision(admin, "alice", "alice@example.com")
    browser = TestClient(app)
    location = browser.get("/api/auth/github/login", follow_redirects=False).headers["location"]
    code = fake.authorize(location)
    state = parse_qs(urlparse(location).query)["state"][0]
    cookie = browser.cookies["ansideck_gh"]
    assert _ok(browser.get(CALLBACK, params={"code": code, "state": state}, follow_redirects=False))
    # An attacker who captured the callback URL replays it with a copy of the cookie.
    replay = TestClient(app)
    replay.cookies.set("ansideck_gh", cookie, path="/")
    assert _refused(
        replay.get(CALLBACK, params={"code": code, "state": state}, follow_redirects=False),
        "failed",
    )


def test_the_redirect_target_is_never_user_controlled(gh) -> None:
    fake, admin = gh
    _provision(admin, "alice", "alice@example.com")
    browser = TestClient(app)
    location = browser.get(
        "/api/auth/github/login", params={"next": "https://evil.example"}, follow_redirects=False
    ).headers["location"]
    assert "evil.example" not in location
    code = fake.authorize(location)
    state = parse_qs(urlparse(location).query)["state"][0]
    response = browser.get(
        CALLBACK,
        params={"code": code, "state": state, "next": "https://evil.example"},
        follow_redirects=False,
    )
    assert response.headers["location"] == "/"
    # a provider-reported error is also just a generic failure
    assert _refused(
        browser.get(CALLBACK, params={"error": "access_denied"}, follow_redirects=False), "failed"
    )


def test_repeated_failures_are_throttled_before_reaching_github(gh) -> None:
    fake, _ = gh
    browser = TestClient(app)
    for _ in range(20):
        browser.get(CALLBACK, follow_redirects=False)
    assert _refused(browser.get("/api/auth/github/login", follow_redirects=False), "failed")
    assert fake.token_requests == 0


# ------------------------------------------------------------- GitHub misbehaving


def test_a_200_response_with_an_error_body_is_a_failure(gh) -> None:
    fake, admin = gh
    _provision(admin, "alice", "alice@example.com")
    fake.token_error = "bad_verification_code"  # HTTP 200, exactly as GitHub does it
    assert _refused(_sign_in(fake)[1], "failed")
    assert "bad_verification_code" in _reasons(admin)[0]
    assert _user_row("alice").sso_subject is None


def test_a_token_endpoint_outage_is_a_failure(gh) -> None:
    fake, admin = gh
    fake.token_status = 503
    assert _refused(_sign_in(fake)[1], "failed")


def test_a_missing_email_scope_is_a_failure_and_still_revokes(gh) -> None:
    fake, admin = gh
    _provision(admin, "alice", "alice@example.com")
    fake.emails_status = 404
    assert _refused(_sign_in(fake)[1], "failed")
    assert "user/emails" in _reasons(admin)[0]
    assert fake.revoked == fake.issued and len(fake.issued) == 1


def test_a_profile_outage_is_a_failure_and_still_revokes(gh) -> None:
    fake, admin = gh
    fake.user_status = 500
    assert _refused(_sign_in(fake)[1], "failed")
    assert fake.revoked == fake.issued and len(fake.issued) == 1


def test_a_profile_without_a_numeric_id_is_refused(gh) -> None:
    fake, admin = gh
    _provision(admin, "alice", "alice@example.com")
    assert _refused(_sign_in(fake, id="alice-gh")[1], "failed")  # the login is not an identity
    assert _refused(_sign_in(fake, id=True)[1], "failed")
    assert _user_row("alice").sso_subject is None


def test_a_failed_revocation_does_not_break_sign_in(gh) -> None:
    fake, admin = gh
    _provision(admin, "alice", "alice@example.com")
    fake.revoke_status = 500
    assert _ok(_sign_in(fake, id=1001)[1])
    fake.revoke_raises = True
    assert _ok(_sign_in(fake, id=1001)[1])


def test_tokens_and_secrets_never_reach_the_audit_log_or_logs(gh, caplog) -> None:
    fake, admin = gh
    _provision(admin, "alice", "alice@example.com")
    with caplog.at_level(logging.DEBUG):
        _sign_in(fake, id=1001)
        _sign_in(fake, id=3003, emails=[_verified("nobody@example.com")])
        fake.emails_status = 403
        _sign_in(fake, id=1001)
    dump = json.dumps(admin.get("/api/audit", params={"limit": 200}).json())
    for secret in [CLIENT_SECRET, "code_verifier", *fake.issued]:
        assert secret not in dump and secret not in caplog.text
    assert len(fake.issued) == 3


# ----------------------------------------------------- alongside OIDC, and the admin UI


def test_github_and_oidc_can_both_be_enabled(fake, client, monkeypatch) -> None:
    for name, value in {"OIDC_ISSUER": "https://idp.test", "OIDC_CLIENT_ID": "c"}.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "s")
    get_settings.cache_clear()
    fake_oidc = FakeOidc()
    monkeypatch.setattr(
        oidc, "http_client", lambda: httpx.Client(transport=httpx.MockTransport(fake_oidc.handle))
    )
    monkeypatch.setattr(
        github_login,
        "http_client",
        lambda: httpx.Client(transport=httpx.MockTransport(fake.handle)),
    )
    browser = TestClient(app)
    body = browser.get("/api/auth/providers").json()
    assert body["oidc"]["enabled"] and body["github"]["enabled"]
    oidc_start = browser.get("/api/auth/oidc/login", follow_redirects=False)
    github_start = browser.get("/api/auth/github/login", follow_redirects=False)
    assert oidc_start.headers["location"].startswith("https://idp.test/authorize?")
    assert github_start.headers["location"].startswith(f"{GITHUB_URL}/login/oauth/authorize?")
    # Independent state cookies, on independent paths.
    assert {"ansideck_oidc", "ansideck_gh"} <= set(browser.cookies.keys())


def test_the_users_list_names_the_provider_and_unlink_works(gh) -> None:
    fake, admin = gh
    uid = _provision(admin, "alice", "alice@example.com")
    _provision(admin, "bob", "bob@example.com")

    def shown(user_id: int) -> dict:
        return next(u for u in admin.get("/api/users").json() if u["id"] == user_id)

    assert shown(uid)["sso_provider"] is None and shown(uid)["sso_linked"] is False
    assert _ok(_sign_in(fake, id=1001)[1])
    assert shown(uid)["sso_provider"] == "GitHub" and shown(uid)["sso_linked"] is True
    assert "sso_issuer" not in shown(uid)  # which provider, not the raw binding

    bob = next(u for u in admin.get("/api/users").json() if u["username"] == "bob")
    db = get_sessionmaker()()
    db.query(User).filter(User.id == bob["id"]).update(
        {"sso_issuer": "https://idp.test", "sso_subject": "b"}
    )
    db.commit()
    db.close()
    assert shown(bob["id"])["sso_provider"] == "SSO"

    assert admin.delete(f"/api/users/{uid}/sso-link").status_code == 204
    assert shown(uid)["sso_provider"] is None
    assert _ok(_sign_in(fake, id=1002)[1])  # a new GitHub account can link after an unlink
