"""Passkeys as a second factor (app.passkeys, the /api/auth/passkeys routes, the passkey step of
signing in) and REQUIRE_ADMIN_2FA, against a software authenticator."""

import types
from datetime import timedelta

import pyotp
import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app import cli, passkeys, totp
from app.config import Settings, get_settings
from app.db import get_sessionmaker
from app.hardening import user_login_throttle
from app.main import app
from app.models import AuditEvent, Project, ProjectMember, User, WebAuthnCredential
from tests.conftest import TEST_PASSWORD, make_user_client
from tests.soft_authenticator import SoftAuthenticator

ORIGIN = "http://localhost"
SYNCED = 0x45 | 0x08 | 0x10  # backup eligible and backed up


@pytest.fixture
def pk(client: TestClient, monkeypatch) -> TestClient:
    """`client`, with passkeys available (PUBLIC_URL=http://localhost) and signed in as admin."""
    monkeypatch.setenv("PUBLIC_URL", ORIGIN)
    get_settings.cache_clear()
    assert _login(client).status_code == 200
    return client


@pytest.fixture
def require_admin_2fa(monkeypatch) -> None:
    monkeypatch.setenv("REQUIRE_ADMIN_2FA", "true")
    get_settings.cache_clear()


def _login(browser: TestClient, username: str = "admin", password: str = "admin"):
    return browser.post("/api/auth/login", json={"username": username, "password": password})


def _add(browser: TestClient, auth: SoftAuthenticator, name: str = "laptop", **create):
    password = create.pop("password", "admin")
    options = browser.post(
        "/api/auth/passkeys/registration/options", json={"current_password": password}
    )
    assert options.status_code == 200, options.text
    credential = auth.create(options.json()["options"], create.pop("origin", ORIGIN), **create)
    return browser.post("/api/auth/passkeys", json={"name": name, "credential": credential})


def _password_step(username: str = "admin", password: str = "admin") -> TestClient:
    browser = TestClient(app)
    assert _login(browser, username, password).json()["mfa_required"] is True
    return browser


def _passkey_step(browser: TestClient, auth: SoftAuthenticator, **get):
    options = browser.post("/api/auth/login/mfa/passkey/options")
    assert options.status_code == 200, options.text
    credential = auth.get(options.json()["options"], get.pop("origin", ORIGIN), **get)
    return browser.post("/api/auth/login/mfa/passkey", json={"credential": credential})


def _audit(action: str) -> list[AuditEvent]:
    db = get_sessionmaker()()
    try:
        return (
            db.query(AuditEvent).filter(AuditEvent.action == action).order_by(AuditEvent.id).all()
        )
    finally:
        db.close()


def _user(username: str = "admin") -> User:
    db = get_sessionmaker()()
    try:
        user = db.query(User).filter(User.username == username).one()
        _ = user.passkeys  # loaded before the session closes
        return user
    finally:
        db.close()


# ------------------------------------------------------------------ relying party


@pytest.mark.parametrize(
    ("public_url", "rp"),
    [
        ("https://ansideck.example.com", ("ansideck.example.com", "https://ansideck.example.com")),
        ("https://AnsiDeck.Example.com:443/", ("ansideck.example.com", "https://ansideck.example.com")),
        ("https://ansideck.example.com:8443", ("ansideck.example.com", "https://ansideck.example.com:8443")),
        ("http://localhost:5173", ("localhost", "http://localhost:5173")),
        ("http://localhost", ("localhost", "http://localhost")),
        ("http://ansideck.example.com", None),  # http only on localhost
        ("https://10.0.0.5", None),  # an IP address can't be a relying party ID
        ("https://[::1]:8443", None),
        ("http://127.0.0.1:5173", None),
        ("", None),
    ],
)  # fmt: skip
def test_the_relying_party_comes_from_public_url(public_url: str, rp) -> None:
    assert Settings(public_url=public_url).passkey_rp == rp


def test_passkeys_are_unavailable_without_a_usable_public_url(client: TestClient) -> None:
    assert _login(client).status_code == 200
    assert client.get("/api/auth/providers").json()["passkeys"] == {
        "enabled": False,
        "origin": None,
    }
    options = client.post(
        "/api/auth/passkeys/registration/options", json={"current_password": "admin"}
    )
    assert options.status_code == 404 and "PUBLIC_URL" in options.json()["detail"]


# ------------------------------------------------------------------ registration


def test_the_first_passkey_comes_with_recovery_codes_and_ends_other_sessions(pk) -> None:
    other = TestClient(app)
    assert _login(other).status_code == 200
    assert pk.get("/api/auth/providers").json()["passkeys"] == {"enabled": True, "origin": ORIGIN}

    added = _add(pk, SoftAuthenticator())
    assert added.status_code == 201, added.text
    body = added.json()
    assert body["passkey"]["name"] == "laptop" and body["passkey"]["synced"] is False
    assert len(body["recovery_codes"]) == 10
    assert other.get("/api/auth/me").status_code == 401  # signed in with the password alone
    me = pk.get("/api/auth/me").json()  # ...but this session got a new cookie
    assert (me["passkey_count"], me["two_factor_enabled"], me["totp_enabled"]) == (1, True, False)

    second = _add(pk, SoftAuthenticator(), "phone", flags=SYNCED)
    assert second.status_code == 201 and second.json()["recovery_codes"] is None
    assert second.json()["passkey"]["synced"] is True
    assert [p["name"] for p in pk.get("/api/auth/passkeys").json()] == ["laptop", "phone"]
    assert pk.get("/api/auth/me").status_code == 200  # adding a second factor signs nobody out
    assert [e.detail["name"] for e in _audit("auth.passkey_add")] == ["laptop", "phone"]


def test_registration_needs_the_password_and_a_fresh_challenge(pk) -> None:
    wrong = pk.post("/api/auth/passkeys/registration/options", json={"current_password": "nope"})
    assert wrong.status_code == 401

    auth = SoftAuthenticator()
    options = pk.post(
        "/api/auth/passkeys/registration/options", json={"current_password": "admin"}
    ).json()["options"]
    assert options["rp"]["id"] == "localhost"
    assert options["authenticatorSelection"]["userVerification"] == "discouraged"
    assert options["attestation"] == "none"
    for bad in (
        auth.create(options, "https://evil.example"),  # another origin
        auth.create(options, ORIGIN, rp_id="evil.example"),  # another relying party
        auth.create({**options, "challenge": "AAAA"}, ORIGIN),  # another challenge
    ):
        rejected = pk.post("/api/auth/passkeys", json={"name": "x", "credential": bad})
        assert rejected.status_code == 400
        # Each try uses the challenge up: the next one needs new options.
        pk.post("/api/auth/passkeys/registration/options", json={"current_password": "admin"})
    answer = {"name": "x", "credential": auth.create(options, ORIGIN)}
    assert pk.post("/api/auth/passkeys", json=answer).status_code == 400  # options replaced
    assert pk.post("/api/auth/passkeys", json=answer).status_code == 400  # and none pending
    assert pk.get("/api/auth/passkeys").json() == []
    reasons = [e.detail["reason"] for e in _audit("auth.passkey_add")]
    assert reasons == ["wrong current password"] + ["bad second factor"] * 4 + ["expired"]


def test_names_and_credentials_are_unique_and_the_count_is_capped(pk, monkeypatch) -> None:
    auth = SoftAuthenticator()
    assert _add(pk, auth).status_code == 201
    assert _add(pk, SoftAuthenticator(), "laptop").status_code == 409  # the name
    assert _add(pk, auth, "again").status_code == 409  # the same authenticator
    blank = pk.post("/api/auth/passkeys", json={"name": "  ", "credential": {}})
    assert blank.status_code == 422
    huge = pk.post("/api/auth/passkeys", json={"name": "x", "credential": {"a": "b" * 70_000}})
    assert huge.status_code == 422

    monkeypatch.setattr(passkeys, "MAX_PER_USER", 1)
    full = pk.post("/api/auth/passkeys/registration/options", json={"current_password": "admin"})
    assert full.status_code == 409 and "at most 1" in full.json()["detail"]


def test_a_challenge_expires(pk, monkeypatch) -> None:
    monkeypatch.setattr(passkeys, "CHALLENGE_TTL", timedelta(seconds=-1))
    added = _add(pk, SoftAuthenticator())
    assert added.status_code == 400 and "took too long" in added.json()["detail"]


# ------------------------------------------------------------------ signing in


def test_signing_in_with_a_passkey(pk) -> None:
    auth = SoftAuthenticator()
    assert _add(pk, auth).status_code == 201

    browser = TestClient(app)
    challenge = _login(browser).json()
    assert challenge == {"mfa_required": True, "methods": ["passkey", "recovery_code"]}
    assert browser.get("/api/auth/me").status_code == 401  # not yet
    signed_in = _passkey_step(browser, auth)
    assert signed_in.status_code == 200, signed_in.text
    assert signed_in.json()["username"] == "admin"
    assert browser.get("/api/auth/me").status_code == 200

    login = _audit("auth.login")[-1]
    assert login.outcome == "success" and login.detail == {"mfa": "passkey"}
    stored = _user().passkeys[0]
    assert stored.sign_count == 1 and stored.last_used_at is not None
    assert pk.get("/api/auth/passkeys").json()[0]["last_used_at"] is not None


def test_the_passkey_step_needs_the_password_step(pk) -> None:
    auth = SoftAuthenticator()
    assert _add(pk, auth).status_code == 201
    stranger = TestClient(app)
    assert stranger.post("/api/auth/login/mfa/passkey/options").status_code == 401
    assert stranger.post("/api/auth/login/mfa/passkey", json={"credential": {}}).status_code == 401


def test_forged_replayed_and_foreign_assertions_are_refused(pk) -> None:
    auth = SoftAuthenticator()
    assert _add(pk, auth).status_code == 201

    forger = SoftAuthenticator()  # the right credential ID, the wrong key
    forger.cred_id = auth.cred_id
    stranger = SoftAuthenticator()  # a passkey that isn't registered
    browser = _password_step()
    for attempt in (
        lambda: _passkey_step(browser, forger),
        lambda: _passkey_step(browser, stranger),
        lambda: _passkey_step(browser, auth, origin="https://evil.example"),
        lambda: _passkey_step(browser, auth, rp_id="evil.example"),
        lambda: _passkey_step(browser, auth, flags=0x04),  # no user presence
    ):
        assert attempt().status_code == 401
    user_login_throttle.clear()  # five misses in a row lock the name out for a while

    # One assertion signs in once: replayed later, its challenge is gone.
    options = browser.post("/api/auth/login/mfa/passkey/options").json()["options"]
    assertion = auth.get(options, ORIGIN)
    assert browser.post("/api/auth/login/mfa/passkey", json={"credential": assertion}).is_success
    again = _password_step()
    assert (
        again.post("/api/auth/login/mfa/passkey", json={"credential": assertion}).status_code == 401
    )

    problems = [
        e.detail.get("passkey_problem") for e in _audit("auth.login") if e.outcome == "failure"
    ]
    assert problems == [
        "bad second factor",
        "unknown passkey",
        "bad second factor",
        "bad second factor",
        "bad second factor",
        "expired",
    ]


def test_a_challenge_for_one_purpose_cannot_be_used_for_another(pk) -> None:
    auth = SoftAuthenticator()
    assert _add(pk, auth).status_code == 201
    browser = _password_step()
    browser.post("/api/auth/login/mfa/passkey/options")  # then the signed-in session asks for...
    step_up = pk.post("/api/auth/passkeys/step-up-options").json()["options"]  # ...these
    answer = auth.get(step_up, ORIGIN)
    assert (
        browser.post("/api/auth/login/mfa/passkey", json={"credential": answer}).status_code == 401
    )


def test_a_counter_that_goes_back_is_refused_and_audited(pk) -> None:
    auth = SoftAuthenticator()
    assert _add(pk, auth).status_code == 201
    assert _passkey_step(_password_step(), auth).status_code == 200
    assert _passkey_step(_password_step(), auth).status_code == 200  # count 2

    auth.count = 0  # a clone, behind the original
    cloned = _passkey_step(_password_step(), auth)
    assert cloned.status_code == 401
    failure = [e for e in _audit("auth.login") if e.outcome == "failure"][-1]
    assert failure.detail["passkey_problem"] == "sign count went back"
    assert _user().passkeys[0].sign_count == 2  # kept, not lowered
    auth.count = 5  # the original moves on and is still accepted
    assert _passkey_step(_password_step(), auth).status_code == 200


def test_synced_passkeys_never_count_and_are_always_accepted(pk) -> None:
    auth = SoftAuthenticator(sign_count_step=0)
    assert _add(pk, auth, flags=SYNCED).status_code == 201
    for _ in range(3):
        assert _passkey_step(_password_step(), auth, flags=0x05 | 0x18).status_code == 200
    assert _user().passkeys[0].sign_count == 0


def test_recovery_codes_stand_in_for_a_passkey(pk) -> None:
    codes = _add(pk, SoftAuthenticator()).json()["recovery_codes"]
    browser = _password_step()
    assert (
        browser.post("/api/auth/login/mfa", json={"code": "123456"}).status_code == 401
    )  # no TOTP
    used = browser.post("/api/auth/login/mfa", json={"recovery_code": codes[0]})
    assert used.status_code == 200
    browser = _password_step()
    assert browser.post("/api/auth/login/mfa", json={"recovery_code": codes[0]}).status_code == 401


def test_passkey_and_code_failures_share_one_throttle(pk) -> None:
    auth = SoftAuthenticator()
    assert _add(pk, auth).status_code == 201
    forger = SoftAuthenticator()
    forger.cred_id = auth.cred_id
    for _ in range(5):
        user_login_throttle.clear()  # as if from other addresses: only the per-user limit holds
        browser = _password_step()
        assert _passkey_step(browser, forger).status_code == 401
        browser.post("/api/auth/login/mfa", json={"recovery_code": "aaaaa-aaaaa"})
    user_login_throttle.clear()
    blocked = _password_step().post("/api/auth/login/mfa/passkey/options")
    assert blocked.status_code == 429 and blocked.headers["Retry-After"] == "900"


# ------------------------------------------------------------------ alongside TOTP


def test_totp_added_after_a_passkey_keeps_the_codes(pk) -> None:
    codes = _add(pk, SoftAuthenticator()).json()["recovery_codes"]
    secret = pk.post("/api/auth/totp/setup", json={"current_password": "admin"}).json()["secret"]
    enabled = pk.post("/api/auth/totp/enable", json={"code": pyotp.TOTP(secret).now()})
    assert enabled.status_code == 200 and enabled.json() == {"recovery_codes": None}
    assert _login(TestClient(app)).json()["methods"] == ["totp", "passkey", "recovery_code"]
    browser = _password_step()
    assert browser.post("/api/auth/login/mfa", json={"recovery_code": codes[1]}).is_success

    fresh = pk.post("/api/auth/recovery-codes", json={"current_password": "admin"})
    assert fresh.status_code == 200 and len(fresh.json()["recovery_codes"]) == 10
    old = pk.post("/api/auth/totp/recovery-codes", json={"current_password": "admin"})
    assert old.status_code == 200  # the deprecated path still answers


def test_turning_totp_off_with_a_passkey_keeps_two_factor_on(pk, monkeypatch) -> None:
    now = [1_800_000_000.0]
    monkeypatch.setattr(totp, "time", types.SimpleNamespace(time=lambda: now[0]))
    auth = SoftAuthenticator()
    assert _add(pk, auth).status_code == 201
    secret = pk.post("/api/auth/totp/setup", json={"current_password": "admin"}).json()["secret"]
    pk.post("/api/auth/totp/enable", json={"code": pyotp.TOTP(secret).at(now[0])})

    step_up = pk.post("/api/auth/passkeys/step-up-options").json()["options"]
    off = pk.post(
        "/api/auth/totp/disable",
        json={"current_password": "admin", "passkey": auth.get(step_up, ORIGIN)},
    )
    assert off.status_code == 200, off.text
    assert _audit("auth.totp_disable")[-1].detail == {"two_factor_off": False}
    me = pk.get("/api/auth/me").json()
    assert (me["totp_enabled"], me["two_factor_enabled"]) == (False, True)
    assert _user().recovery_code_hashes  # the codes stay with the passkey


# ------------------------------------------------------------------ managing passkeys


def test_renaming_and_removing_a_passkey(pk) -> None:
    auth = SoftAuthenticator()
    codes = _add(pk, auth).json()["recovery_codes"]
    other = SoftAuthenticator()
    assert _add(pk, other, "phone").status_code == 201
    laptop, phone = (p["id"] for p in pk.get("/api/auth/passkeys").json())

    assert pk.patch(f"/api/auth/passkeys/{laptop}", json={"name": "phone"}).status_code == 409
    renamed = pk.patch(f"/api/auth/passkeys/{laptop}", json={"name": " work laptop "})
    assert renamed.status_code == 200 and renamed.json()["name"] == "work laptop"
    assert _audit("auth.passkey_rename")[-1].detail["was"] == "laptop"

    # Removing takes the password and a current second factor.
    remove = f"/api/auth/passkeys/{phone}/remove"
    assert pk.post(remove, json={"current_password": "admin"}).status_code == 422
    wrong = {"current_password": "nope", "code": codes[0]}
    assert pk.post(remove, json=wrong).status_code == 401
    assert pk.post(remove, json={"current_password": "admin", "code": "x" * 10}).status_code == 401
    step_up = pk.post("/api/auth/passkeys/step-up-options").json()["options"]
    removed = pk.post(
        remove, json={"current_password": "admin", "passkey": other.get(step_up, ORIGIN)}
    )
    assert removed.status_code == 200  # (with the passkey being removed)
    assert _audit("auth.passkey_remove")[-1].detail == {
        "passkey_id": phone,
        "name": "phone",
        "two_factor_off": False,
    }

    # The last one takes the recovery codes with it.
    last = pk.post(
        f"/api/auth/passkeys/{laptop}/remove", json={"current_password": "admin", "code": codes[1]}
    )
    assert last.status_code == 200
    assert _audit("auth.passkey_remove")[-1].detail["two_factor_off"] is True
    assert _user().recovery_code_hashes is None
    assert _login(TestClient(app)).json()["username"] == "admin"  # the password alone again
    assert pk.post(f"/api/auth/passkeys/{laptop}/remove", json=wrong).status_code == 401


def test_nobody_reaches_someone_elses_passkeys(pk) -> None:
    assert _add(pk, SoftAuthenticator()).status_code == 201
    admins = pk.get("/api/auth/passkeys").json()[0]["id"]
    operator = make_user_client("op", "operator")
    assert operator.get("/api/auth/passkeys").json() == []
    assert operator.patch(f"/api/auth/passkeys/{admins}", json={"name": "mine"}).status_code == 404
    proof = {"current_password": TEST_PASSWORD, "code": "aaaaa-aaaaa"}
    assert operator.post(f"/api/auth/passkeys/{admins}/remove", json=proof).status_code == 404
    assert operator.post("/api/auth/passkeys/step-up-options").status_code == 404  # has none
    assert len(_user().passkeys) == 1


def test_an_admin_reset_removes_passkeys_too(pk, capsys) -> None:
    operator = make_user_client("op", "operator", password=TEST_PASSWORD)
    pk.post("/api/auth/logout")
    _login(pk, "op", TEST_PASSWORD)
    assert _add(pk, SoftAuthenticator(), password=TEST_PASSWORD).status_code == 201
    assert operator.get("/api/auth/me").status_code == 401  # (the first factor ended it)

    admin = TestClient(app)
    assert _login(admin).status_code == 200
    listed = {u["username"]: u for u in admin.get("/api/users").json()}
    assert (listed["op"]["passkey_count"], listed["op"]["two_factor_enabled"]) == (1, True)
    assert admin.delete(f"/api/users/{listed['op']['id']}/two-factor").status_code == 204
    assert pk.get("/api/auth/me").status_code == 401
    user = _user("op")
    assert (user.passkeys, user.recovery_code_hashes, user.webauthn_pending) == ([], None, None)
    assert _audit("user.two_factor_reset")[-1].detail == {"totp": False, "passkeys": 1}

    # The break-glass CLI does the same.
    _login(admin, "op", TEST_PASSWORD)
    assert _add(admin, SoftAuthenticator(), password=TEST_PASSWORD).status_code == 201
    assert cli.main(["reset-2fa", "op"]) == 0
    assert _user("op").passkeys == []
    db = get_sessionmaker()()
    try:
        assert db.query(WebAuthnCredential).count() == 0
    finally:
        db.close()


# ------------------------------------------------------------------ REQUIRE_ADMIN_2FA


def _project_admin(username: str) -> TestClient:
    browser = make_user_client(username, "viewer", default_membership=False)
    db = get_sessionmaker()()
    try:
        user = db.query(User).filter(User.username == username).one()
        default = db.query(Project).filter(Project.name == "Default").one()
        db.add(ProjectMember(project_id=default.id, user_id=user.id, role="admin"))
        db.commit()
    finally:
        db.close()
    return browser


def test_admins_must_set_up_a_second_factor_first(pk, require_admin_2fa) -> None:
    browser = TestClient(app)
    out = _login(browser).json()
    assert out["two_factor_setup_required"] is True
    assert _audit("auth.login")[-1].detail == {"two_factor_setup_required": True}

    refused = browser.get("/api/playbooks")
    assert (
        refused.status_code == 403 and refused.json()["detail"] == "Set up two-factor login first"
    )
    denied = _audit("permission.denied")[-1]
    assert denied.detail["reason"] == "two-factor setup required"
    assert browser.post("/api/auth/change-password", json={}).status_code in (403, 422)
    assert browser.get("/api/auth/me").json()["two_factor_setup_required"] is True
    assert browser.get("/api/auth/passkeys").status_code == 200

    assert _add(browser, SoftAuthenticator()).status_code == 201
    assert browser.get("/api/playbooks").status_code == 200
    assert browser.get("/api/auth/me").json()["two_factor_setup_required"] is False


def test_project_admins_are_held_too_but_not_operators_sso_or_keys(pk, require_admin_2fa) -> None:
    project_admin = _project_admin("padmin")
    assert project_admin.get("/api/playbooks").status_code == 403
    operator = make_user_client("op", "operator")
    assert operator.get("/api/playbooks").status_code == 200
    assert operator.get("/api/auth/me").json()["two_factor_setup_required"] is False


def test_the_run_websocket_refuses_a_session_that_must_set_up_2fa(pk, require_admin_2fa) -> None:
    browser = TestClient(app)
    _login(browser)
    with pytest.raises(WebSocketDisconnect) as closed, browser.websocket_connect("/api/runs/1/ws"):
        pass
    assert closed.value.code == 1008


def test_an_admin_keeps_a_last_second_factor(pk, require_admin_2fa) -> None:
    codes = _add(pk, SoftAuthenticator()).json()["recovery_codes"]
    passkey = pk.get("/api/auth/passkeys").json()[0]["id"]
    kept = pk.post(
        f"/api/auth/passkeys/{passkey}/remove", json={"current_password": "admin", "code": codes[0]}
    )
    assert kept.status_code == 409 and "keep a second factor" in kept.json()["detail"]
    assert len(_user().passkeys) == 1
