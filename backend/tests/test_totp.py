import json
import re
import types

import pyotp
import pytest
from fastapi.testclient import TestClient

from app import cli, totp
from app.db import get_sessionmaker
from app.hardening import user_login_throttle
from app.main import app
from app.models import AuditEvent, User
from tests.conftest import TEST_PASSWORD, make_user_client

# RFC 6238 appendix B: the SHA-1 key "12345678901234567890" at T=59 gives 94287082.
RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
START = 1_800_000_000  # a multiple of 30: step boundaries are easy to reason about


@pytest.fixture
def clock(monkeypatch) -> list[float]:
    """Moves only the TOTP clock (session/MFA cookies keep real time)."""
    now = [float(START)]
    monkeypatch.setattr(totp, "time", types.SimpleNamespace(time=lambda: now[0]))
    return now


def _code(secret: str, clock: list[float]) -> str:
    return pyotp.TOTP(secret).at(clock[0])


def _login(browser: TestClient, username: str = "admin", password: str = "admin"):
    return browser.post("/api/auth/login", json={"username": username, "password": password})


def _enable(
    browser: TestClient, clock: list[float], password: str = "admin"
) -> tuple[str, list[str]]:
    setup = browser.post("/api/auth/totp/setup", json={"current_password": password})
    assert setup.status_code == 200, setup.text
    secret = setup.json()["secret"]
    enabled = browser.post("/api/auth/totp/enable", json={"code": _code(secret, clock)})
    assert enabled.status_code == 200, enabled.text
    clock[0] += 30  # the enable code's time step is used up
    return secret, enabled.json()["recovery_codes"]


def _mfa(browser: TestClient, **body):
    return browser.post("/api/auth/login/mfa", json=body)


def _audit_rows() -> list[dict]:
    db = get_sessionmaker()()
    try:
        return [
            {c.name: str(getattr(e, c.name)) for c in AuditEvent.__table__.columns}
            for e in db.query(AuditEvent).all()
        ]
    finally:
        db.close()


# --- code matching ------------------------------------------------------------------


def test_match_counter_follows_rfc_6238_and_allows_one_step_of_drift() -> None:
    assert totp.match_counter(RFC_SECRET, "287082", None, now=59) == 1
    assert totp.match_counter(RFC_SECRET, "287 082", None, now=59) == 1
    assert totp.match_counter(RFC_SECRET, "287082", None, now=59 + 30) == 1  # a step late
    assert totp.match_counter(RFC_SECRET, "287082", None, now=59 - 30) == 1  # a step early
    assert totp.match_counter(RFC_SECRET, "287082", None, now=59 + 60) is None


def test_match_counter_rejects_replays_and_anything_but_six_ascii_digits() -> None:
    assert totp.match_counter(RFC_SECRET, "287082", 1, now=59) is None  # step 1 already used
    assert totp.match_counter(RFC_SECRET, "287082", 0, now=59) == 1
    for bad in ["28708", "2870820", "28708a", "", "٢٨٧٠٨٢", "287-082"]:
        assert totp.match_counter(RFC_SECRET, bad, None, now=59) is None


def test_recovery_codes_are_distinct_formatted_and_single_use() -> None:
    codes, hashes = totp.new_recovery_codes()
    assert len(set(codes)) == len(set(hashes)) == totp.RECOVERY_CODE_COUNT
    assert all(re.fullmatch(r"[a-z2-9]{5}-[a-z2-9]{5}", c) for c in codes)

    user = User(totp_secret=b"x", totp_recovery_hashes=hashes)
    typed = codes[3].upper().replace("-", " ")
    assert totp.use_second_factor(user, code=None, recovery_code=typed) == "recovery_code"
    assert len(user.totp_recovery_hashes) == totp.RECOVERY_CODE_COUNT - 1
    assert totp.use_second_factor(user, code=None, recovery_code=codes[3]) is None
    assert totp.use_second_factor(user, code=None, recovery_code="\ud800" * 10) is None


# --- setup ------------------------------------------------------------------------------


def test_setup_needs_the_password_and_returns_a_scannable_uri(client: TestClient) -> None:
    _login(client)
    assert client.post("/api/auth/totp/setup", json={"current_password": "x"}).status_code == 401

    setup = client.post("/api/auth/totp/setup", json={"current_password": "admin"}).json()
    assert re.fullmatch(r"[A-Z2-7]{32}", setup["secret"])
    assert setup["otpauth_uri"].startswith("otpauth://totp/AnsiDeck:admin?")
    assert f"secret={setup['secret']}" in setup["otpauth_uri"]
    assert setup["qr"].startswith("data:image/svg+xml")
    assert client.get("/api/auth/me").json()["totp_enabled"] is False  # not until a code


def test_enable_needs_a_valid_code_and_signs_out_other_sessions(client: TestClient, clock) -> None:
    _login(client)
    other = TestClient(app)
    _login(other)
    assert client.post("/api/auth/totp/enable", json={"code": "123456"}).status_code == 400

    secret = client.post("/api/auth/totp/setup", json={"current_password": "admin"}).json()[
        "secret"
    ]
    wrong = f"{(int(_code(secret, clock)) + 1) % 1_000_000:06d}"
    assert client.post("/api/auth/totp/enable", json={"code": wrong}).status_code == 400
    enabled = client.post("/api/auth/totp/enable", json={"code": _code(secret, clock)})
    assert enabled.status_code == 200
    assert len(enabled.json()["recovery_codes"]) == totp.RECOVERY_CODE_COUNT

    assert client.get("/api/auth/me").json()["totp_enabled"] is True
    assert other.get("/api/auth/me").status_code == 401
    again = client.post("/api/auth/totp/setup", json={"current_password": "admin"})
    assert again.status_code == 409


def test_the_secret_is_encrypted_at_rest(client: TestClient, clock) -> None:
    _login(client)
    secret, _ = _enable(client, clock)
    db = get_sessionmaker()()
    admin = db.query(User).filter(User.username == "admin").one()
    assert secret.encode() not in admin.totp_secret
    assert totp.decrypt(admin.totp_secret) == secret
    db.close()


# --- two-step login ---------------------------------------------------------------------


def test_password_alone_no_longer_signs_in(client: TestClient, clock) -> None:
    _login(client)
    secret, _ = _enable(client, clock)
    browser = TestClient(app)

    response = _login(browser)
    assert response.status_code == 200 and response.json() == {"mfa_required": True}
    assert "ansideck_session" not in response.headers.get("set-cookie", "")
    assert browser.get("/api/auth/me").status_code == 401
    assert _login(browser, password="wrong").status_code == 401  # unchanged for a bad password

    _login(browser)
    signed_in = _mfa(browser, code=_code(secret, clock))
    assert signed_in.status_code == 200 and signed_in.json()["username"] == "admin"
    assert browser.get("/api/auth/me").status_code == 200


def test_a_code_works_only_once(client: TestClient, clock) -> None:
    _login(client)
    secret, _ = _enable(client, clock)
    code = _code(secret, clock)

    first, second = TestClient(app), TestClient(app)
    _login(first)
    _login(second)
    assert _mfa(first, code=code).status_code == 200
    assert _mfa(second, code=code).status_code == 401
    clock[0] += 30
    assert _mfa(second, code=_code(secret, clock)).status_code == 200


def test_recovery_codes_sign_in_once_each(client: TestClient, clock) -> None:
    _login(client)
    _, codes = _enable(client, clock)
    browser = TestClient(app)

    _login(browser)
    assert _mfa(browser, recovery_code=codes[0].upper()).status_code == 200
    browser.post("/api/auth/logout")
    _login(browser)
    assert _mfa(browser, recovery_code=codes[0]).status_code == 401

    logins = client.get("/api/audit", params={"action": "auth.login", "limit": 50}).json()
    by_code = [e["detail"] for e in logins["items"] if (e["detail"] or {}).get("mfa")]
    assert by_code == [{"mfa": "recovery_code", "recovery_codes_left": 9}]


def test_the_second_step_needs_a_fresh_password_step(client: TestClient, clock) -> None:
    _login(client)
    secret, _ = _enable(client, clock)
    browser = TestClient(app)
    code = _code(secret, clock)

    assert _mfa(browser, code=code).status_code == 401  # no password step at all
    browser.cookies.set("ansideck_mfa", "forged", path="/api/auth/login")
    assert _mfa(browser, code=code).status_code == 401
    # A session token is signed with a different salt, so it can't stand in.
    session = client.cookies.get("ansideck_session")
    browser.cookies.clear()
    browser.cookies.set("ansideck_mfa", session, path="/api/auth/login")
    assert _mfa(browser, code=code).status_code == 401

    browser.cookies.clear()
    _login(browser)
    db = get_sessionmaker()()
    db.query(User).filter(User.username == "admin").one().session_version += 1
    db.commit()
    db.close()
    assert _mfa(browser, code=code).status_code == 401  # e.g. password changed meanwhile
    assert _mfa(browser).status_code == 422
    assert _mfa(browser, code=code, recovery_code="x").status_code == 422


def test_wrong_codes_are_throttled_per_ip_and_per_user(client: TestClient, clock) -> None:
    _login(client)
    secret, _ = _enable(client, clock)
    browser = TestClient(app)
    _login(browser)

    assert [_mfa(browser, code="000000").status_code for _ in range(5)] == [401] * 5
    blocked = _mfa(browser, code=_code(secret, clock))
    assert blocked.status_code == 429 and "login attempts" in blocked.json()["detail"]

    user_login_throttle.clear()  # as if the guesses moved to another address
    _login(browser)
    assert [_mfa(browser, code="000000").status_code for _ in range(5)] == [401] * 5
    user_login_throttle.clear()  # and again: the per-user limit still holds
    blocked = _mfa(browser, code=_code(secret, clock))
    assert blocked.status_code == 429 and "wrong codes" in blocked.json()["detail"]
    assert blocked.headers["Retry-After"] == "900"

    failures = [
        e for e in _audit_rows() if e["action"] == "auth.login" and e["outcome"] == "failure"
    ]
    assert len(failures) == 10 and all("bad second factor" in e["detail"] for e in failures)


def test_a_correct_password_does_not_reset_the_throttle_before_the_code(
    client: TestClient, clock
) -> None:
    _login(client)
    secret, _ = _enable(client, clock)
    browser = TestClient(app)
    for _ in range(5):
        _login(browser)
        assert _mfa(browser, code="000000").status_code == 401
    assert _login(browser).status_code == 429


# --- managing it ------------------------------------------------------------------------


def test_disable_needs_the_password_and_a_code(client: TestClient, clock) -> None:
    _login(client)
    secret, codes = _enable(client, clock)

    def disable(password: str, code: str) -> int:
        body = {"current_password": password, "code": code}
        return client.post("/api/auth/totp/disable", json=body).status_code

    assert disable("wrong", _code(secret, clock)) == 401
    assert disable("admin", "000000") == 401
    assert disable("admin", "not-a-recovery-code") == 401
    assert client.get("/api/auth/me").json()["totp_enabled"] is True
    assert disable("admin", codes[5]) == 200
    assert client.get("/api/auth/me").json()["totp_enabled"] is False
    assert _login(TestClient(app)).json()["username"] == "admin"  # password alone again


def test_disable_with_a_totp_code(client: TestClient, clock) -> None:
    _login(client)
    secret, _ = _enable(client, clock)
    body = {"current_password": "admin", "code": _code(secret, clock)}
    assert client.post("/api/auth/totp/disable", json=body).status_code == 200
    assert _login(TestClient(app)).json()["username"] == "admin"


def test_regenerating_recovery_codes_invalidates_the_old_ones(client: TestClient, clock) -> None:
    _login(client)
    _, old = _enable(client, clock)
    fresh = client.post("/api/auth/totp/recovery-codes", json={"current_password": "admin"})
    assert fresh.status_code == 200
    new = fresh.json()["recovery_codes"]
    assert set(new).isdisjoint(old)

    browser = TestClient(app)
    _login(browser)
    assert _mfa(browser, recovery_code=old[0]).status_code == 401
    assert _mfa(browser, recovery_code=new[0]).status_code == 200


def test_an_admin_can_reset_someone_elses_two_factor_login(client: TestClient, clock) -> None:
    _login(client)
    user = make_user_client("totp-user", "operator")
    _enable(user, clock, password=TEST_PASSWORD)
    listed = {u["username"]: u for u in client.get("/api/users").json()}
    assert listed["totp-user"]["totp_enabled"] is True

    reset = client.delete(f"/api/users/{listed['totp-user']['id']}/totp")
    assert reset.status_code == 204
    assert user.get("/api/auth/me").status_code == 401  # signed out
    assert _login(TestClient(app), "totp-user", TEST_PASSWORD).json()["username"] == "totp-user"

    admin_id = listed["admin"]["id"]
    assert client.delete(f"/api/users/{admin_id}/totp").status_code == 400
    assert user.delete(f"/api/users/{admin_id}/totp").status_code in (401, 403)
    assert any(e["action"] == "user.totp_reset" for e in _audit_rows())


def test_the_server_cli_is_the_break_glass(client: TestClient, clock, capsys) -> None:
    _login(client)
    _enable(client, clock)

    assert cli.main(["reset-totp", "admin"]) == 0
    assert "turned off" in capsys.readouterr().out
    assert _login(TestClient(app)).json()["username"] == "admin"
    assert client.get("/api/auth/me").status_code == 401  # sessions signed out
    assert cli.main(["reset-totp", "admin"]) == 0  # nothing left to do
    assert cli.main(["reset-totp", "nobody"]) == 1

    row = next(e for e in _audit_rows() if e["action"] == "user.totp_reset")
    assert row["actor_username"] == "(server cli)" and row["target_name"] == "admin"


def test_secrets_and_codes_never_reach_the_audit_log(client: TestClient, clock) -> None:
    _login(client)
    secret, codes = _enable(client, clock)
    browser = TestClient(app)
    _login(browser)
    _mfa(browser, recovery_code="plantedwrongcode")
    _mfa(browser, recovery_code=codes[1])
    client.post("/api/auth/totp/recovery-codes", json={"current_password": "admin"})

    dump = json.dumps(_audit_rows()).lower()
    for planted in [secret, *codes, codes[1].replace("-", ""), "plantedwrongcode"]:
        assert planted.lower() not in dump
