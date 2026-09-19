import hashlib
import json
import re
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.api_keys import parse_prefix
from app.db import get_sessionmaker
from app.main import app
from app.models import ApiKey
from tests.routes import iter_api_routes
from tests.test_projects import _admin, _member, _populate, _project
from tests.test_rbac import PUBLIC, _walk
from tests.test_runs import _wait_for_completion


@pytest.fixture
def world(client: TestClient):
    admin = _admin(client)
    a, b = _project(admin, "Team A"), _project(admin, "Team B")
    return {"admin": admin, "a": _populate(admin, a, "a"), "b": _populate(admin, b, "b")}


def _create_key(admin: TestClient, project_id: int, name="ci", preset="trigger", **extra) -> dict:
    response = admin.post(
        f"/api/projects/{project_id}/api-keys", json={"name": name, "preset": preset, **extra}
    )
    assert response.status_code == 201, response.text
    return response.json()


def _key_client(token: str) -> TestClient:
    return TestClient(app, headers={"Authorization": f"Bearer {token}"})


def _run_body(p: dict, **extra) -> dict:
    return {
        "playbook_id": p["playbook"],
        "inventory_id": p["inventory"],
        "credential_id": p["credential"],
        **extra,
    }


def _set(key_id: int, **fields) -> None:
    db = get_sessionmaker()()
    row = db.get(ApiKey, key_id)
    for name, value in fields.items():
        setattr(row, name, value)
    db.commit()
    db.close()


# ------------------------------------------------------------------ management


def test_token_is_shown_once_and_only_a_hash_is_stored(world) -> None:
    admin, a = world["admin"], world["a"]
    created = _create_key(admin, a["project"])
    token = created["token"]
    assert token.startswith("ansd_")
    assert parse_prefix(token) == created["prefix"]
    assert created["status"] == "active"

    listed = admin.get(f"/api/projects/{a['project']}/api-keys")
    assert listed.status_code == 200
    assert token not in listed.text
    assert all("token" not in item and "token_hash" not in item for item in listed.json())

    db = get_sessionmaker()()
    row = db.get(ApiKey, created["id"])
    assert row.token_hash == hashlib.sha256(token.encode()).hexdigest()
    stored = json.dumps({c.name: str(getattr(row, c.name)) for c in ApiKey.__table__.columns})
    assert token not in stored
    db.close()


def test_key_management_is_for_project_admins_only(world) -> None:
    admin, a, b = world["admin"], world["a"], world["b"]
    project_admin = _member(admin, "proj-admin", {a["project"]: "admin"})
    operator = _member(admin, "proj-op", {a["project"]: "operator"})
    viewer = _member(admin, "proj-viewer", {a["project"]: "viewer"})
    outsider = _member(admin, "outsider", {b["project"]: "admin"})
    path = f"/api/projects/{a['project']}/api-keys"

    assert (
        project_admin.post(path, json={"name": "from-admin", "preset": "trigger"}).status_code
        == 201
    )
    for denied in (operator, viewer):
        assert denied.get(path).status_code == 403
        assert denied.post(path, json={"name": "x", "preset": "trigger"}).status_code == 403
    # A member of another project can't tell the project exists.
    assert outsider.get(path).status_code == 404
    assert outsider.post(path, json={"name": "x", "preset": "trigger"}).status_code == 404
    assert TestClient(app).get(path).status_code == 401


def test_a_project_admin_cannot_revoke_or_see_another_projects_keys(world) -> None:
    admin, a, b = world["admin"], world["a"], world["b"]
    victim = _create_key(admin, a["project"], name="victim")
    key = _key_client(victim["token"])
    admin_of_b = _member(admin, "admin-of-b", {b["project"]: "admin"})

    # Not a member of A: A's key routes look like they don't exist.
    assert admin_of_b.get(f"/api/projects/{a['project']}/api-keys").status_code == 404
    assert (
        admin_of_b.delete(f"/api/projects/{a['project']}/api-keys/{victim['id']}").status_code
        == 404
    )
    # A member of B addressing A's key id through B's own path: still not found.
    assert (
        admin_of_b.delete(f"/api/projects/{b['project']}/api-keys/{victim['id']}").status_code
        == 404
    )
    assert admin_of_b.get(f"/api/projects/{b['project']}/api-keys").json() == []
    assert key.get("/api/runs").status_code == 200  # the key is untouched


def test_create_validates_and_rejects_duplicates(world) -> None:
    admin, a = world["admin"], world["a"]
    path = f"/api/projects/{a['project']}/api-keys"
    _create_key(admin, a["project"], name="dup")
    assert admin.post(path, json={"name": "dup", "preset": "read-only"}).status_code == 409
    for bad in (
        {"name": "has space", "preset": "trigger"},
        {"name": "apikey:x", "preset": "trigger"},
        {"name": "ok", "preset": "admin"},
        {"name": "ok", "preset": "trigger", "expires_in_days": 0},
        {"name": "ok", "preset": "trigger", "expires_in_days": 366},
    ):
        assert admin.post(path, json=bad).status_code == 422, bad


def test_active_keys_per_project_are_capped(world) -> None:
    admin, a = world["admin"], world["a"]
    path = f"/api/projects/{a['project']}/api-keys"
    for i in range(50):
        _create_key(admin, a["project"], name=f"k{i}")
    assert admin.post(path, json={"name": "one-too-many", "preset": "trigger"}).status_code == 409


def test_key_roles_cannot_be_assigned_to_members(world) -> None:
    admin, a = world["admin"], world["a"]
    member = _member(admin, "someone", {a["project"]: "viewer"})
    uid = next(u["id"] for u in admin.get("/api/users").json() if u["username"] == "someone")
    del member
    response = admin.put(
        f"/api/projects/{a['project']}/members/{uid}", json={"role": "key:trigger"}
    )
    assert response.status_code in (400, 422)


def test_listing_shows_status_and_deleting_a_project_removes_its_keys(world) -> None:
    admin = world["admin"]
    empty = _project(admin, "Empty")
    live = _create_key(admin, empty, name="live")
    old = _create_key(admin, empty, name="old")
    gone = _create_key(admin, empty, name="gone")
    _set(old["id"], expires_at=datetime.now(UTC) - timedelta(days=1))
    assert admin.delete(f"/api/projects/{empty}/api-keys/{gone['id']}").status_code == 204

    statuses = {k["name"]: k["status"] for k in admin.get(f"/api/projects/{empty}/api-keys").json()}
    assert statuses == {"live": "active", "old": "expired", "gone": "revoked"}
    assert live["id"]

    assert admin.delete(f"/api/projects/{empty}").status_code == 204
    db = get_sessionmaker()()
    assert db.query(ApiKey).filter(ApiKey.project_id == empty).count() == 0
    db.close()


# ---------------------------------------------------------------------- using a key


def test_trigger_key_starts_a_run_and_polls_it_to_completion(world) -> None:
    a = world["a"]
    key = _key_client(_create_key(world["admin"], a["project"], name="ci-deploy")["token"])

    created = key.post("/api/runs", json=_run_body(a, extra_vars={"greeting": "from-ci"}))
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["triggered_by"] == "apikey:ci-deploy"
    assert body["project_id"] == a["project"]
    assert body["extra_vars"] == {"greeting": "[HIDDEN]"}  # keys never read extra_vars back

    run = _wait_for_completion(key, body["id"])
    assert run["status"] == "success"
    assert run["extra_vars"] == {"greeting": "[HIDDEN]"}
    assert {r["id"] for r in key.get("/api/runs").json()} == {a["run"], body["id"]}


def test_read_only_key_can_read_runs_but_not_trigger_them(world) -> None:
    a = world["a"]
    key = _key_client(_create_key(world["admin"], a["project"], preset="read-only")["token"])
    assert key.get(f"/api/runs/{a['run']}").status_code == 200
    assert [r["id"] for r in key.get("/api/runs").json()] == [a["run"]]
    assert key.post("/api/runs", json=_run_body(a)).status_code == 403


def test_a_key_is_confined_to_its_own_project(world) -> None:
    a, b = world["a"], world["b"]
    key = _key_client(_create_key(world["admin"], a["project"])["token"])
    assert key.get(f"/api/runs/{b['run']}").status_code == 404
    assert key.get("/api/runs", params={"project_id": b["project"]}).status_code == 404
    assert key.post("/api/runs", json=_run_body(b)).status_code == 404
    # Mixing: A's playbook with B's credential is refused too.
    mixed = _run_body(a, credential_id=b["credential"])
    assert key.post("/api/runs", json=mixed).status_code in (400, 404)
    with pytest.raises(WebSocketDisconnect):
        with key.websocket_connect(f"/api/runs/{b['run']}/ws"):
            pass


def test_a_key_cannot_use_become(world) -> None:
    a = world["a"]
    key = _key_client(_create_key(world["admin"], a["project"])["token"])
    response = key.post("/api/runs", json=_run_body(a, become=True))
    assert response.status_code == 403
    assert "become" in response.json()["detail"]


def test_a_key_cannot_reach_any_other_endpoint(world) -> None:
    a = world["a"]
    key = _key_client(_create_key(world["admin"], a["project"], name="probe")["token"])
    calls = [
        ("GET", "/api/auth/me", None),
        ("POST", "/api/auth/change-password", {"current_password": "x", "new_password": "y" * 14}),
        ("GET", "/api/playbooks", None),
        ("POST", "/api/playbooks", {"name": "evil.yml", "content": "- hosts: all"}),
        ("GET", "/api/inventories", None),
        ("GET", "/api/credentials", None),
        ("GET", "/api/vault-passwords", None),
        ("POST", "/api/vault/decrypt", {"vault_password_id": 1, "ciphertext": "x"}),
        ("GET", "/api/galaxy/requirements", None),
        ("GET", "/api/users", None),
        ("GET", "/api/projects", None),
        ("GET", f"/api/projects/{a['project']}/members", None),
        ("GET", f"/api/projects/{a['project']}/api-keys", None),
        ("POST", f"/api/projects/{a['project']}/api-keys", {"name": "mine", "preset": "trigger"}),
        ("GET", "/api/audit", None),
    ]
    for method, path, body in calls:
        response = key.request(method, path, json=body)
        assert response.status_code == 403, f"{method} {path} -> {response.status_code}"
        assert "API keys cannot use this endpoint" in response.json()["detail"]


def test_a_key_is_refused_on_every_served_operation_except_the_run_routes(world) -> None:
    """Behavioural twin of the pinned-set test below: probes what the app actually
    serves (OpenAPI), so a route added later can't quietly become key-accessible."""
    a = world["a"]
    key = _key_client(_create_key(world["admin"], a["project"], name="sweep")["token"])
    allowed = {("GET", "/api/runs"), ("POST", "/api/runs"), ("GET", "/api/runs/{run_id}")}
    probed = 0
    for path, operations in app.openapi()["paths"].items():
        for method in operations:
            if (path, method.upper()) in PUBLIC or (method.upper(), path) in allowed:
                continue
            url = re.sub(r"\{[^}]+\}", "1", path)
            response = key.request(method.upper(), url, json={})
            assert response.status_code == 403, f"{method.upper()} {path} -> {response.status_code}"
            probed += 1
    assert probed > 25  # guards against the sweep silently covering nothing


def test_only_the_run_routes_are_enabled_for_api_keys() -> None:
    enabled = set()
    for route in iter_api_routes(app):
        if any(getattr(d.call, "_allows_api_key", False) for d in _walk(route.dependant)):
            enabled |= {(method, route.path) for method in route.methods}
    assert enabled == {
        ("GET", "/api/runs"),
        ("POST", "/api/runs"),
        ("GET", "/api/runs/{run_id}"),
    }


# ---------------------------------------------------------------- bad and dead keys


def test_bad_tokens_are_rejected_generically(world) -> None:
    a = world["a"]
    real = _create_key(world["admin"], a["project"])["token"]
    prefix = parse_prefix(real)
    for token in (
        "garbage",
        "ansd_zzzzzzzz_secret",
        f"ansd_00000000_{'x' * 43}",  # well-formed, unknown prefix
        f"ansd_{prefix}_{'x' * 43}",  # real prefix, wrong secret
        real + "0",
        "x" * 500,
    ):
        response = _key_client(token).get("/api/runs")
        assert response.status_code == 401, token
        assert response.json()["detail"] == "Invalid API key"
        assert response.headers["www-authenticate"] == "Bearer"
    for header in ("Basic abc", "Bearer", "Bearer   ", real):  # wrong scheme / empty
        response = TestClient(app).get("/api/runs", headers={"Authorization": header})
        assert response.status_code == 401, header


def test_revoking_takes_effect_immediately(world) -> None:
    admin, a = world["admin"], world["a"]
    created = _create_key(admin, a["project"])
    key = _key_client(created["token"])
    assert key.get("/api/runs").status_code == 200

    path = f"/api/projects/{a['project']}/api-keys/{created['id']}"
    assert admin.delete(path).status_code == 204
    assert admin.delete(path).status_code == 204  # idempotent
    assert key.get("/api/runs").status_code == 401
    assert admin.delete(f"/api/projects/{a['project']}/api-keys/999999").status_code == 404


def test_an_expired_key_stops_working(world) -> None:
    created = _create_key(world["admin"], world["a"]["project"])
    key = _key_client(created["token"])
    assert key.get("/api/runs").status_code == 200
    _set(created["id"], expires_at=datetime.now(UTC) - timedelta(seconds=1))
    assert key.get("/api/runs").status_code == 401


def test_a_bad_key_does_not_fall_back_to_a_valid_session_cookie(world) -> None:
    admin = world["admin"]  # holds a valid admin cookie
    assert admin.get("/api/runs").status_code == 200
    response = admin.get("/api/runs", headers={"Authorization": "Bearer ansd_00000000_nope"})
    assert response.status_code == 401


def test_repeated_bad_keys_are_throttled(world) -> None:
    good = _create_key(world["admin"], world["a"]["project"])["token"]
    bad = _key_client(f"ansd_00000000_{'y' * 43}")
    assert [bad.get("/api/runs").status_code for _ in range(20)] == [401] * 20
    assert bad.get("/api/runs").status_code == 429
    assert _key_client(good).get("/api/runs").status_code == 429  # same client address


# ----------------------------------------------------------------- audit / bookkeeping


def test_audit_trail_names_the_key_and_never_holds_a_token(world) -> None:
    admin, a = world["admin"], world["a"]
    created = _create_key(admin, a["project"], name="audited")
    key = _key_client(created["token"])
    run_id = key.post("/api/runs", json=_run_body(a)).json()["id"]
    _wait_for_completion(key, run_id)
    key.get("/api/auth/me")  # denied
    _key_client(f"ansd_{created['prefix']}_{'z' * 43}").get("/api/runs")  # bad secret
    admin.delete(f"/api/projects/{a['project']}/api-keys/{created['id']}")

    events = admin.get("/api/audit", params={"limit": 200}).json()["items"]
    by_action = {}
    for event in events:
        by_action.setdefault(event["action"], []).append(event)

    trigger = next(e for e in by_action["run.trigger"] if e["target_id"] == run_id)
    assert trigger["actor_username"] == "apikey:audited"
    assert trigger["detail"]["api_key_id"] == created["id"]
    assert trigger["project_id"] == a["project"]
    assert by_action["apikey.create"][0]["target_name"] == "audited"
    assert by_action["apikey.revoke"][0]["target_id"] == created["id"]
    failure = by_action["apikey.auth"][0]
    assert failure["outcome"] == "failure"
    assert failure["actor_username"] == f"apikey:{created['prefix']}"
    assert failure["detail"]["reason"] == "bad secret"
    assert any(
        e["detail"].get("api_key_id") == created["id"] for e in by_action["permission.denied"]
    )

    dump = json.dumps(events)
    assert created["token"] not in dump
    assert "z" * 43 not in dump


def test_last_used_is_recorded(world) -> None:
    admin, a = world["admin"], world["a"]
    created = _create_key(admin, a["project"])
    assert created["last_used_at"] is None
    _key_client(created["token"]).get("/api/runs")
    listed = admin.get(f"/api/projects/{a['project']}/api-keys").json()
    assert listed[0]["last_used_at"] is not None
    assert listed[0]["last_used_ip"]


# ---------------------------------------------------------------------- websocket


def test_websocket_log_stream_accepts_a_key_header(world) -> None:
    admin, a = world["admin"], world["a"]
    token = _create_key(admin, a["project"])["token"]
    header = {"Authorization": f"Bearer {token}"}
    with TestClient(app).websocket_connect(f"/api/runs/{a['run']}/ws", headers=header) as ws:
        first = json.loads(ws.receive_text())
    assert "event" in first

    for headers in ({}, {"Authorization": "Bearer ansd_00000000_nope"}):
        with pytest.raises(WebSocketDisconnect):
            with TestClient(app).websocket_connect(
                f"/api/runs/{a['run']}/ws", headers=headers
            ) as ws:
                ws.receive_text()
