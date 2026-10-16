"""GitHub sign-in limited to orgs and teams (GITHUB_ALLOWED_ORGS / GITHUB_ALLOWED_TEAMS), and
project memberships managed from teams (GITHUB_TEAM_ROLE_MAP)."""

# ruff: noqa: F811 - tests take the GitHub and TOTP fixtures imported below

import json
import logging

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from app import sso_common
from app.config import Settings, get_settings
from app.db import get_sessionmaker
from app.main import app
from app.models import ProjectMember, User
from app.routers import sso as sso_router
from tests.fake_github import CLIENT_SECRET, LINK_HOST, ORG_SCOPE, FakeGithub
from tests.test_github_login import _reasons, _sign_in, _user_row, fake, gh  # noqa: F401
from tests.test_projects import _project
from tests.test_sso import PASSWORD, _audit, _ok, _provision, _refused
from tests.test_totp import _enable, _mfa, clock  # noqa: F401

ACME = {"Acme": "active"}  # GitHub's own capitalisation; the settings say "acme"


def _configure(monkeypatch, fake: FakeGithub, **settings) -> None:
    for name, value in settings.items():
        monkeypatch.setenv(name, value if isinstance(value, str) else json.dumps(value))
    get_settings.cache_clear()
    fake.expected_scope = ORG_SCOPE


def _members(project_id: int) -> dict[str, tuple[str, str | None]]:
    db = get_sessionmaker()()
    try:
        rows = (
            db.query(User.username, ProjectMember.role, ProjectMember.granted_by)
            .join(User, User.id == ProjectMember.user_id)
            .filter(ProjectMember.project_id == project_id)
            .all()
        )
        return {name: (role, granted_by) for name, role, granted_by in rows}
    finally:
        db.close()


def _not_allowed_reason(admin: TestClient) -> str:
    # The action filter is a prefix: auth.sso also finds auth.sso_link.
    return next(
        e["detail"]["reason"] for e in _audit(admin, "auth.sso") if e["action"] == "auth.sso"
    )


# --------------------------------------------------------------------- configuration


def test_the_gate_settings_are_normalised_and_bad_values_refused() -> None:
    base = {"github_client_id": "c", "github_client_secret": "s", "public_url": "http://x"}
    settings = Settings(
        **base,
        github_allowed_orgs=[" Acme ", "acme", "beta-co"],
        github_allowed_teams=["Acme/Ops"],
        github_team_role_map={"Acme/Ops": {" Default ": "operator"}},
    )
    assert settings.github_allowed_orgs == ["acme", "beta-co"]
    assert settings.github_allowed_teams == ["acme/ops"]
    assert settings.github_team_role_map == {"acme/ops": {"Default": "operator"}}
    assert settings.github_gated and settings.github_needs_org_data
    assert settings.github_relevant_orgs == ["acme", "beta-co"]

    # Org logins go into an API path: nothing that could change it gets through.
    for org in ["../acme", "acme/ops", "ac me", "-acme", "acme?x=1", ""]:
        with pytest.raises(ValueError, match="not a GitHub org"):
            Settings(**base, github_allowed_orgs=[org])
    for team in ["acme", "acme/", "/ops", "acme/ops/x", "../x/ops"]:
        with pytest.raises(ValueError, match="not a GitHub team"):
            Settings(**base, github_allowed_teams=[team])
    # The map grants project roles only: never the global admin role, nothing unknown.
    for role in ["owner", "superadmin", "Admin", ""]:
        with pytest.raises(ValueError, match="gives project"):
            Settings(**base, github_team_role_map={"acme/ops": {"Default": role}})
    with pytest.raises(ValueError, match="1 to 100 projects"):
        Settings(**base, github_team_role_map={"acme/ops": {}})
    with pytest.raises(ValueError, match="invalid project name"):
        Settings(**base, github_team_role_map={"acme/ops": {" ": "viewer"}})
    with pytest.raises(ValueError, match="twice"):
        Settings(**base, github_team_role_map={"acme/ops": {"a": "viewer"}, "Acme/Ops": {}})
    with pytest.raises(ValueError, match="at most 10 orgs"):
        Settings(**base, github_allowed_teams=[f"org{i}/t" for i in range(11)])
    with pytest.raises(ValueError, match="more than 10 orgs"):
        Settings(**base, github_allowed_orgs=[f"org{i}" for i in range(11)])


def test_the_gate_settings_need_github_sign_in() -> None:
    for setting in [
        {"github_allowed_orgs": ["acme"]},
        {"github_allowed_teams": ["acme/ops"]},
        {"github_team_role_map": {"acme/ops": {"Default": "viewer"}}},
    ]:
        with pytest.raises(ValueError, match="need GITHUB_CLIENT_ID"):
            Settings(**setting)


def test_the_settings_are_read_as_json_from_the_environment(monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_CLIENT_ID", "c")
    monkeypatch.setenv("GITHUB_CLIENT_SECRET", "s")
    monkeypatch.setenv("PUBLIC_URL", "http://x")
    monkeypatch.setenv("GITHUB_ALLOWED_ORGS", '["acme"]')
    monkeypatch.setenv("GITHUB_TEAM_ROLE_MAP", '{"acme/ops": {"Default": "admin"}}')
    settings = Settings()
    assert settings.github_allowed_orgs == ["acme"]
    assert settings.github_team_role_map == {"acme/ops": {"Default": "admin"}}


# ------------------------------------------------------------------------ the scope


def test_read_org_is_asked_for_only_when_something_needs_it(gh, monkeypatch) -> None:
    fake, admin = gh
    _provision(admin, "alice", "alice@example.com")
    assert _ok(_sign_in(fake, id=1001)[1])  # fake asserts the plain scope
    assert not [r for r in fake.requests if "/memberships/" in r[2] or r[2] == "/user/teams"]

    _configure(monkeypatch, fake, GITHUB_ALLOWED_ORGS=["acme"])
    assert _ok(_sign_in(fake, id=1001, orgs=ACME)[1])  # fake asserts read:org is asked for


def test_a_user_who_unticks_read_org_is_refused(gh, monkeypatch) -> None:
    fake, admin = gh
    _provision(admin, "alice", "alice@example.com")
    _configure(monkeypatch, fake, GITHUB_ALLOWED_ORGS=["acme"])
    _b, response = _sign_in(fake, id=1001, orgs=ACME, granted_scope="read:user,user:email")
    assert _refused(response, "failed")
    assert "did not grant the read:org scope" in _reasons(admin)[0]
    assert fake.revoked == fake.issued


# ------------------------------------------------------------------------- the gate


def test_an_active_member_of_an_allowed_org_signs_in(gh, monkeypatch) -> None:
    fake, admin = gh
    _provision(admin, "alice", "alice@example.com")
    _configure(monkeypatch, fake, GITHUB_ALLOWED_ORGS=["acme"])
    assert _ok(_sign_in(fake, id=1001, orgs=ACME)[1])
    login = _audit(admin, "auth.login")[0]
    assert login["detail"] == {"method": "github", "matched": "org acme"}
    assert fake.revoked == fake.issued


@pytest.mark.parametrize(
    ("orgs", "restricted", "reason"),
    [
        ({"Acme": "pending"}, set(), "is pending (invitation not accepted)"),
        ({}, set(), "not a member of an allowed GitHub org or team"),
        ({"Other": "active"}, set(), "not a member of an allowed GitHub org or team"),
        (ACME, {"acme"}, "GitHub org acme restricts OAuth apps: an org owner must approve"),
    ],
)
def test_everyone_else_is_refused_and_not_linked(gh, monkeypatch, orgs, restricted, reason) -> None:
    fake, admin = gh
    _provision(admin, "alice", "alice@example.com")
    _configure(monkeypatch, fake, GITHUB_ALLOWED_ORGS=["acme"])
    fake.restricted_orgs = restricted
    browser, response = _sign_in(fake, id=1001, orgs=orgs)
    assert _refused(response, "not_allowed")
    assert browser.get("/api/auth/me").status_code == 401
    assert reason in _not_allowed_reason(admin)
    assert _user_row("alice").sso_subject is None  # refused before anything is linked
    assert fake.revoked == fake.issued


def test_an_allowed_team_lets_its_direct_members_in(gh, monkeypatch) -> None:
    fake, admin = gh
    _provision(admin, "alice", "alice@example.com")
    _configure(monkeypatch, fake, GITHUB_ALLOWED_TEAMS=["acme/ops"])
    assert _ok(_sign_in(fake, id=1001, orgs=ACME, teams=[("Acme", "Ops")])[1])
    assert _audit(admin, "auth.login")[0]["detail"]["matched"] == "team acme/ops"
    # Another team of the same org isn't enough, nor is the team while the org invite pends.
    other = _sign_in(fake, id=1001, orgs=ACME, teams=[("Acme", "dev")])[1]
    assert _refused(other, "not_allowed")
    pending = _sign_in(fake, id=1001, orgs={"Acme": "pending"}, teams=[("Acme", "ops")])[1]
    assert _refused(pending, "not_allowed")
    assert "pending" in _not_allowed_reason(admin)


def test_the_gate_applies_at_every_sign_in_not_just_the_first(gh, monkeypatch) -> None:
    fake, admin = gh
    _provision(admin, "alice", "alice@example.com")
    _configure(monkeypatch, fake, GITHUB_ALLOWED_ORGS=["acme"])
    assert _ok(_sign_in(fake, id=1001, orgs=ACME)[1])
    assert _refused(_sign_in(fake, id=1001, orgs={})[1], "not_allowed")  # left the org
    failure = _audit(admin, "auth.sso")[0]
    assert failure["actor_username"] == "alice"  # the linked user is named


def test_other_refusals_and_states_count_as_no_membership(gh, monkeypatch) -> None:
    fake, admin = gh
    _provision(admin, "alice", "alice@example.com")
    _configure(monkeypatch, fake, GITHUB_ALLOWED_ORGS=["acme"])
    assert _refused(_sign_in(fake, id=1001, orgs={"Acme": "suspended"})[1], "not_allowed")
    fake.memberships_status = 403  # a 403 that isn't about OAuth app restrictions
    assert _refused(_sign_in(fake, id=1001, orgs=ACME)[1], "not_allowed")
    assert "not a member" in _not_allowed_reason(admin)


def test_a_malformed_teams_answer_fails_closed(gh, monkeypatch) -> None:
    fake, admin = gh
    _provision(admin, "alice", "alice@example.com")
    _configure(monkeypatch, fake, GITHUB_ALLOWED_TEAMS=["acme/ops"])
    fake.teams_body = {"message": "not a list"}
    assert _refused(_sign_in(fake, id=1001, orgs=ACME, teams=[("Acme", "ops")])[1], "failed")
    assert "unexpected response from GitHub /user/teams" in _reasons(admin)[0]
    fake.teams_body = [{"slug": 7, "organization": {"login": "Acme"}}, "junk"]
    assert _refused(_sign_in(fake, id=1001, orgs=ACME, teams=[("Acme", "ops")])[1], "not_allowed")


@pytest.mark.parametrize("knob", ["memberships_status", "teams_status", "rate_limited"])
def test_github_trouble_fails_closed(gh, monkeypatch, knob) -> None:
    fake, admin = gh
    _provision(admin, "alice", "alice@example.com")
    _configure(monkeypatch, fake, GITHUB_ALLOWED_TEAMS=["acme/ops"])
    setattr(fake, knob, True if knob == "rate_limited" else 502)
    _b, response = _sign_in(fake, id=1001, orgs=ACME, teams=[("Acme", "ops")])
    assert _refused(response, "failed")
    assert fake.revoked == fake.issued


def test_every_read_happens_before_the_token_is_revoked(gh, monkeypatch, caplog) -> None:
    fake, admin = gh
    _provision(admin, "alice", "alice@example.com")
    _project(admin, "Ops")
    _configure(
        monkeypatch,
        fake,
        GITHUB_ALLOWED_ORGS=["acme"],
        GITHUB_TEAM_ROLE_MAP={"acme/ops": {"Ops": "operator"}},
    )
    with caplog.at_level(logging.DEBUG):
        assert _ok(_sign_in(fake, id=1001, orgs=ACME, teams=[("Acme", "ops")])[1])
        assert _refused(_sign_in(fake, id=1001, orgs={})[1], "not_allowed")
    api = [(m, p) for m, host, p, _q in fake.requests if "api." in host]
    assert api == 2 * [
        ("GET", "/user"),
        ("GET", "/user/emails"),
        ("GET", "/user/memberships/orgs/acme"),
        ("GET", "/user/teams"),
        ("DELETE", "/applications/ansideck-gh-client/token"),
    ]
    dump = json.dumps(admin.get("/api/audit", params={"limit": 200}).json())
    for secret in [CLIENT_SECRET, *fake.issued]:
        assert secret not in dump and secret not in caplog.text


# ---------------------------------------------------------------------- pagination


def test_teams_are_read_page_by_page_without_following_link_headers(gh, monkeypatch) -> None:
    fake, admin = gh
    _provision(admin, "alice", "alice@example.com")
    _configure(monkeypatch, fake, GITHUB_ALLOWED_TEAMS=["acme/ops"])
    teams = [("Acme", f"t{i:03}") for i in range(249)] + [("Acme", "ops")]  # ops on page 3
    assert _ok(_sign_in(fake, id=1001, orgs=ACME, teams=teams)[1])
    pages = [q["page"] for _m, _h, p, q in fake.requests if p == "/user/teams"]
    assert pages == ["1", "2", "3"]
    assert not [r for r in fake.requests if r[1] == LINK_HOST]

    fake.requests.clear()
    exactly = [("Acme", f"t{i:03}") for i in range(99)] + [("Acme", "ops")]
    assert _ok(_sign_in(fake, id=1001, orgs=ACME, teams=exactly)[1])
    assert len([r for r in fake.requests if r[2] == "/user/teams"]) == 2  # page 2 is empty


def test_more_teams_than_it_reads_fails_closed(gh, monkeypatch) -> None:
    fake, admin = gh
    _provision(admin, "alice", "alice@example.com")
    _configure(monkeypatch, fake, GITHUB_ALLOWED_TEAMS=["acme/ops"])
    teams = [("Acme", f"t{i:04}") for i in range(1000)] + [("Acme", "ops")]
    assert _refused(_sign_in(fake, id=1001, orgs=ACME, teams=teams)[1], "failed")
    assert "more than 1000 GitHub teams" in _reasons(admin)[0]


# ------------------------------------------------------------------ the team mapping


def _mapped(monkeypatch, fake, role_map: dict, **more) -> None:
    _configure(monkeypatch, fake, GITHUB_TEAM_ROLE_MAP=role_map, **more)


def test_mapped_teams_add_change_and_remove_memberships(gh, monkeypatch) -> None:
    fake, admin = gh
    _provision(admin, "alice", "alice@example.com")
    ops, web = _project(admin, "Ops"), _project(admin, "Web")
    _mapped(
        monkeypatch,
        fake,
        {"acme/ops": {"Ops": "operator", "Web": "viewer"}, "acme/leads": {"Ops": "admin"}},
    )
    sign_in = {"id": 1001, "orgs": ACME}
    assert _ok(_sign_in(fake, **sign_in, teams=[("Acme", "ops")])[1])
    assert _members(ops)["alice"] == ("operator", "github")
    assert _members(web)["alice"] == ("viewer", "github")
    added = [e for e in _audit(admin, "project.member_add") if "via" in e["detail"]]
    assert {(e["project_id"], e["detail"]["via"]) for e in added} == {
        (ops, "github team acme/ops"),
        (web, "github team acme/ops"),
    }
    assert {e["actor_username"] for e in added} == {"(github team sync)"}

    # Joined a second team: the higher role wins.
    assert _ok(_sign_in(fake, **sign_in, teams=[("Acme", "ops"), ("Acme", "leads")])[1])
    assert _members(ops)["alice"] == ("admin", "github")
    change = _audit(admin, "project.member_role_change")[0]
    assert change["detail"] == {
        "via": "github team acme/leads",
        "role": "admin",
        "previous_role": "operator",
    }

    # Left both teams: both memberships go.
    assert _ok(_sign_in(fake, **sign_in, teams=[])[1])
    assert "alice" not in _members(ops) and "alice" not in _members(web)
    assert len(_audit(admin, "project.member_remove")) == 2
    # The global role was never touched.
    assert _user_row("alice").role == "operator"


def test_an_org_membership_must_be_active_for_its_teams_to_count(gh, monkeypatch) -> None:
    fake, admin = gh
    _provision(admin, "alice", "alice@example.com")
    ops = _project(admin, "Ops")
    _mapped(monkeypatch, fake, {"acme/ops": {"Ops": "operator"}})
    assert _ok(_sign_in(fake, id=1001, orgs={"Acme": "pending"}, teams=[("Acme", "ops")])[1])
    assert "alice" not in _members(ops)


def test_memberships_set_by_hand_are_never_touched(gh, monkeypatch) -> None:
    fake, admin = gh
    alice = _provision(admin, "alice", "alice@example.com")
    ops = _project(admin, "Ops")
    assert admin.put(f"/api/projects/{ops}/members/{alice}", json={"role": "viewer"}).is_success
    _mapped(monkeypatch, fake, {"acme/ops": {"Ops": "admin"}})
    assert _ok(_sign_in(fake, id=1001, orgs=ACME, teams=[("Acme", "ops")])[1])
    assert _members(ops)["alice"] == ("viewer", None)
    assert _audit(admin, "auth.login")[0]["detail"]["kept_manual"] == [ops]
    assert _ok(_sign_in(fake, id=1001, orgs=ACME, teams=[])[1])
    assert _members(ops)["alice"] == ("viewer", None)


def test_unknown_project_names_are_skipped_and_audited(gh, monkeypatch) -> None:
    fake, admin = gh
    _provision(admin, "alice", "alice@example.com")
    _mapped(monkeypatch, fake, {"acme/ops": {"Gone": "viewer", "Also gone": "admin"}})
    assert _ok(_sign_in(fake, id=1001, orgs=ACME, teams=[("Acme", "ops")])[1])
    assert _audit(admin, "auth.login")[0]["detail"]["unknown_projects"] == ["Also gone", "Gone"]


def test_removing_the_map_removes_what_it_granted_at_the_next_sign_in(gh, monkeypatch) -> None:
    fake, admin = gh
    _provision(admin, "alice", "alice@example.com")
    ops = _project(admin, "Ops")
    _mapped(monkeypatch, fake, {"acme/ops": {"Ops": "operator"}})
    assert _ok(_sign_in(fake, id=1001, orgs=ACME, teams=[("Acme", "ops")])[1])
    monkeypatch.delenv("GITHUB_TEAM_ROLE_MAP")
    get_settings.cache_clear()
    fake.expected_scope = "read:user user:email"
    assert _ok(_sign_in(fake, id=1001)[1])
    assert "alice" not in _members(ops)


def test_a_failed_membership_sync_ends_without_a_session(gh, monkeypatch) -> None:
    fake, admin = gh
    _provision(admin, "alice", "alice@example.com")
    _project(admin, "Ops")
    _mapped(monkeypatch, fake, {"acme/ops": {"Ops": "operator"}})

    def broken(*_args, **_kwargs):
        raise OperationalError("UPDATE", {}, Exception("database went away"))

    monkeypatch.setattr(sso_router, "sync_managed_memberships", broken)
    browser, response = _sign_in(fake, id=1001, orgs=ACME, teams=[("Acme", "ops")])
    assert _refused(response, "failed")
    assert "project membership sync failed" in _reasons(admin)[0]
    assert browser.get("/api/auth/me").status_code == 401


def test_ties_name_the_first_team_so_the_audit_trail_is_stable() -> None:
    grants, unknown = sso_common.desired_memberships(
        _OneProject(), {"b/x": {"P": "viewer"}, "a/x": {"P": "viewer"}}, ["b/x", "a/x"]
    )
    assert (grants, unknown) == ({7: sso_common.Grant("viewer", "a/x")}, [])


class _OneProject:
    """Stands in for a session whose database has one project, "P" (id 7)."""

    def query(self, *_columns):
        return self

    def filter(self, *_conditions):
        return self

    def all(self):
        return [("P", 7)]


# ------------------------------------------------ password sign-ins, edits, unlinking


def _github_operator(admin: TestClient, fake: FakeGithub, monkeypatch) -> tuple[int, int]:
    alice = _provision(admin, "alice", "alice@example.com")
    ops = _project(admin, "Ops")
    _mapped(monkeypatch, fake, {"acme/ops": {"Ops": "operator"}})
    assert _ok(_sign_in(fake, id=1001, orgs=ACME, teams=[("Acme", "ops")])[1])
    assert _members(ops)["alice"] == ("operator", "github")
    return alice, ops


def test_a_password_sign_in_drops_github_granted_memberships(gh, monkeypatch) -> None:
    fake, admin = gh
    _alice, ops = _github_operator(admin, fake, monkeypatch)
    default = admin.get("/api/projects").json()
    manual = [p["id"] for p in default if p["name"] == "Default"]
    browser = TestClient(app)
    login = browser.post("/api/auth/login", json={"username": "alice", "password": PASSWORD})
    assert login.status_code == 200, login.text
    assert "alice" not in _members(ops)
    assert all("alice" in _members(p) for p in manual)  # set by hand: kept
    removed = _audit(admin, "project.member_remove")[0]
    assert removed["actor_username"] == "alice" and removed["detail"]["via"] == "password sign-in"
    # And back at the next GitHub sign-in.
    assert _ok(_sign_in(fake, id=1001, orgs=ACME, teams=[("Acme", "ops")])[1])
    assert _members(ops)["alice"] == ("operator", "github")


def test_a_two_factor_sign_in_drops_them_too(gh, monkeypatch, clock) -> None:
    fake, admin = gh
    _alice, ops = _github_operator(admin, fake, monkeypatch)
    browser = TestClient(app)
    assert browser.post(
        "/api/auth/login", json={"username": "alice", "password": PASSWORD}
    ).is_success
    _secret, codes = _enable(browser, clock, password=PASSWORD)
    # Signing in again (with the password) needs the second factor now.
    assert _ok(_sign_in(fake, id=1001, orgs=ACME, teams=[("Acme", "ops")])[1])
    assert _members(ops)["alice"] == ("operator", "github")
    fresh = TestClient(app)
    step = fresh.post("/api/auth/login", json={"username": "alice", "password": PASSWORD})
    assert step.json().get("methods"), step.text
    assert "alice" in _members(ops)  # not before the second factor
    assert _mfa(fresh, recovery_code=codes[0]).is_success
    assert "alice" not in _members(ops)


def test_setting_a_managed_membership_by_hand_makes_it_manual(gh, monkeypatch) -> None:
    fake, admin = gh
    alice, ops = _github_operator(admin, fake, monkeypatch)
    members = admin.get(f"/api/projects/{ops}/members").json()
    assert [m["granted_by"] for m in members if m["username"] == "alice"] == ["github"]
    same = admin.put(f"/api/projects/{ops}/members/{alice}", json={"role": "operator"})
    assert same.status_code == 200 and same.json()["granted_by"] is None
    change = _audit(admin, "project.member_role_change")[0]
    assert change["detail"] == {"role": "operator", "was_managed_by": "github"}
    # Now the mapping leaves it alone, even after leaving the team.
    assert _ok(_sign_in(fake, id=1001, orgs=ACME, teams=[])[1])
    assert _members(ops)["alice"] == ("operator", None)


def test_removing_a_managed_membership_is_audited(gh, monkeypatch) -> None:
    fake, admin = gh
    alice, ops = _github_operator(admin, fake, monkeypatch)
    assert admin.delete(f"/api/projects/{ops}/members/{alice}").status_code == 204
    removed = _audit(admin, "project.member_remove")[0]
    assert removed["actor_username"] == "admin"
    assert removed["detail"] == {"was_managed_by": "github"}


def test_unlinking_the_identity_drops_what_it_granted(gh, monkeypatch) -> None:
    fake, admin = gh
    alice, ops = _github_operator(admin, fake, monkeypatch)
    assert admin.delete(f"/api/users/{alice}/sso-link").status_code == 204
    assert "alice" not in _members(ops)
    removed = _audit(admin, "project.member_remove")[0]
    assert removed["actor_username"] == "admin" and removed["detail"]["via"] == "sso unlink"
