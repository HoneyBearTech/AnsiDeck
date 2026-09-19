import sqlite3

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.config import get_settings
from app.crypto import hash_password
from app.db import get_engine, get_sessionmaker, init_db
from app.main import app
from app.permissions import Permission, Scope
from tests.conftest import make_user_client
from tests.test_rbac import _walk
from tests.test_runs import _generate_key_pem, _wait_for_completion

PLAYBOOK = (
    "- hosts: all\n  connection: local\n  gather_facts: false\n  tasks:\n"
    "    - ansible.builtin.copy:\n        content: hi\n        dest: /tmp/ansideck-project-test\n"
)


def _admin(client: TestClient) -> TestClient:
    assert (
        client.post("/api/auth/login", json={"username": "admin", "password": "admin"}).status_code
        == 200
    )
    return client


def _project(admin: TestClient, name: str) -> int:
    response = admin.post("/api/projects", json={"name": name})
    assert response.status_code == 201, response.text
    return response.json()["id"]


def _user_id(admin: TestClient, username: str) -> int:
    return next(u["id"] for u in admin.get("/api/users").json() if u["username"] == username)


def _member(admin: TestClient, username: str, memberships: dict[int, str], global_role="viewer"):
    """A logged-in client for a user whose ONLY memberships are `memberships`."""
    user_client = make_user_client(username, global_role, default_membership=False)
    uid = _user_id(admin, username)
    for project_id, role in memberships.items():
        response = admin.put(f"/api/projects/{project_id}/members/{uid}", json={"role": role})
        assert response.status_code == 200, response.text
    return user_client


def _populate(admin: TestClient, project_id: int, tag: str) -> dict:
    """One of every project-owned resource, created by the global admin."""
    body = {"project_id": project_id}
    playbook = admin.post("/api/playbooks", json={"name": f"pb-{tag}", "content": PLAYBOOK, **body})
    inventory = admin.post("/api/inventories", json={"name": f"inv-{tag}", **body})
    inv_id = inventory.json()["id"]
    group = admin.post(f"/api/inventories/{inv_id}/groups", json={"name": f"g-{tag}"})
    host = admin.post(f"/api/inventories/{inv_id}/hosts", json={"hostname": f"h-{tag}"})
    credential = admin.post(
        "/api/credentials", json={"name": f"cred-{tag}", "private_key": _generate_key_pem(), **body}
    )
    vault = admin.post(
        "/api/vault-passwords",
        json={"name": f"vault-{tag}", "password": f"pw-{tag}-secret", **body},
    )
    for response in (playbook, inventory, group, host, credential, vault):
        assert response.status_code == 201, response.text
    run = admin.post(
        "/api/runs",
        json={
            "playbook_id": playbook.json()["id"],
            "inventory_id": inv_id,
            "credential_id": credential.json()["id"],
            "extra_vars": {"greeting": f"hello-{tag}"},
        },
    )
    assert run.status_code == 201, run.text
    _wait_for_completion(admin, run.json()["id"])
    return {
        "project": project_id,
        "playbook": playbook.json()["id"],
        "inventory": inv_id,
        "group": group.json()["id"],
        "host": host.json()["id"],
        "credential": credential.json()["id"],
        "vault": vault.json()["id"],
        "run": run.json()["id"],
    }


@pytest.fixture
def world(client: TestClient):
    admin = _admin(client)
    a, b = _project(admin, "Team A"), _project(admin, "Team B")
    return {"admin": admin, "a": _populate(admin, a, "a"), "b": _populate(admin, b, "b")}


# ---------------------------------------------------------------- IDOR


def _idor_calls(b: dict) -> list[tuple[str, str, dict | None]]:
    inv, run = b["inventory"], b["run"]
    return [
        ("GET", f"/api/playbooks/{b['playbook']}", None),
        ("PUT", f"/api/playbooks/{b['playbook']}", {"name": "hijack"}),
        ("DELETE", f"/api/playbooks/{b['playbook']}", None),
        ("GET", f"/api/inventories/{inv}", None),
        ("PUT", f"/api/inventories/{inv}", {"name": "hijack"}),
        ("DELETE", f"/api/inventories/{inv}", None),
        ("POST", f"/api/inventories/{inv}/groups", {"name": "x"}),
        ("PUT", f"/api/inventories/{inv}/groups/{b['group']}", {"name": "x"}),
        ("DELETE", f"/api/inventories/{inv}/groups/{b['group']}", None),
        ("POST", f"/api/inventories/{inv}/hosts", {"hostname": "x"}),
        ("PUT", f"/api/inventories/{inv}/hosts/{b['host']}", {"hostname": "x"}),
        ("DELETE", f"/api/inventories/{inv}/hosts/{b['host']}", None),
        ("DELETE", f"/api/credentials/{b['credential']}", None),
        ("DELETE", f"/api/vault-passwords/{b['vault']}", None),
        ("GET", f"/api/runs/{run}", None),
        (
            "POST",
            "/api/vault/encrypt",
            {"vault_password_id": b["vault"], "plaintext": "x"},
        ),
        (
            "POST",
            "/api/vault/decrypt",
            {"vault_password_id": b["vault"], "ciphertext": "x"},
        ),
    ]


def test_user_in_project_a_cannot_reach_anything_in_project_b(world) -> None:
    admin, a, b = world["admin"], world["a"], world["b"]
    # An admin-in-A (project admin) — the most privileged non-global identity.
    only_a = _member(admin, "only-a", {a["project"]: "admin"})

    for method, path, body in _idor_calls(b):
        response = only_a.request(method, path, json=body)
        assert response.status_code == 404, f"{method} {path} -> {response.status_code}"

    with pytest.raises(WebSocketDisconnect):
        with only_a.websocket_connect(f"/api/runs/{b['run']}/ws"):
            pass

    # nothing of B was touched
    assert admin.get(f"/api/playbooks/{b['playbook']}").json()["name"] == "pb-b"
    assert admin.get(f"/api/inventories/{b['inventory']}").status_code == 200


def test_same_calls_work_against_their_own_project(world) -> None:
    admin, a = world["admin"], world["a"]
    only_a = _member(admin, "only-a", {a["project"]: "admin"})
    assert only_a.get(f"/api/playbooks/{a['playbook']}").status_code == 200
    assert only_a.get(f"/api/inventories/{a['inventory']}").status_code == 200
    assert only_a.get(f"/api/runs/{a['run']}").status_code == 200
    assert (
        only_a.post(
            "/api/vault/encrypt", json={"vault_password_id": a["vault"], "plaintext": "x"}
        ).status_code
        == 200
    )
    with only_a.websocket_connect(f"/api/runs/{a['run']}/ws") as ws:
        assert ws.receive_text()  # replay of the finished run


def test_lists_only_contain_the_callers_projects(world) -> None:
    admin, a, b = world["admin"], world["a"], world["b"]
    only_a = _member(admin, "only-a", {a["project"]: "operator"})

    for path, key in (
        ("/api/playbooks", "playbook"),
        ("/api/inventories", "inventory"),
        ("/api/credentials", "credential"),
        ("/api/vault-passwords", "vault"),
    ):
        ids = {row["id"] for row in only_a.get(path).json()}
        assert ids == {a[key]}, path
        assert b[key] not in ids
    assert {r["id"] for r in only_a.get("/api/runs").json()} == {a["run"]}

    # explicit filter on a project you don't belong to looks like a missing project
    assert only_a.get("/api/playbooks", params={"project_id": b["project"]}).status_code == 404

    # the global admin sees everything, and can filter
    assert {p["id"] for p in admin.get("/api/playbooks").json()} == {a["playbook"], b["playbook"]}
    filtered = admin.get("/api/playbooks", params={"project_id": b["project"]}).json()
    assert [p["id"] for p in filtered] == [b["playbook"]]


def test_creating_into_a_foreign_project_looks_like_a_missing_project(world) -> None:
    admin, a, b = world["admin"], world["a"], world["b"]
    only_a = _member(admin, "only-a", {a["project"]: "admin"})
    for path, body in (
        ("/api/playbooks", {"name": "x", "content": PLAYBOOK}),
        ("/api/inventories", {"name": "x-inv"}),
        ("/api/credentials", {"name": "x-cred", "private_key": _generate_key_pem()}),
        ("/api/vault-passwords", {"name": "x-vault", "password": "pw"}),
    ):
        response = only_a.post(path, json={**body, "project_id": b["project"]})
        assert response.status_code == 404, path


def test_every_project_scoped_route_with_an_id_is_covered_by_the_idor_matrix() -> None:
    covered = {
        ("GET", "/api/playbooks/{playbook_id}"),
        ("PUT", "/api/playbooks/{playbook_id}"),
        ("DELETE", "/api/playbooks/{playbook_id}"),
        ("GET", "/api/inventories/{inventory_id}"),
        ("PUT", "/api/inventories/{inventory_id}"),
        ("DELETE", "/api/inventories/{inventory_id}"),
        ("POST", "/api/inventories/{inventory_id}/groups"),
        ("PUT", "/api/inventories/{inventory_id}/groups/{group_id}"),
        ("DELETE", "/api/inventories/{inventory_id}/groups/{group_id}"),
        ("POST", "/api/inventories/{inventory_id}/hosts"),
        ("PUT", "/api/inventories/{inventory_id}/hosts/{host_id}"),
        ("DELETE", "/api/inventories/{inventory_id}/hosts/{host_id}"),
        ("DELETE", "/api/credentials/{credential_id}"),
        ("DELETE", "/api/vault-passwords/{vault_password_id}"),
        ("GET", "/api/runs/{run_id}"),
    }
    # project + member routes are exercised by the projects API tests below
    covered |= {
        ("PATCH", "/api/projects/{project_id}"),
        ("DELETE", "/api/projects/{project_id}"),
        ("GET", "/api/projects/{project_id}/members"),
        ("PUT", "/api/projects/{project_id}/members/{user_id}"),
        ("DELETE", "/api/projects/{project_id}/members/{user_id}"),
    }
    found = set()
    for route in app.routes:
        if not isinstance(route, APIRoute) or "{" not in route.path:
            continue
        scopes = {
            getattr(d.call, "_scope", None)
            for d in _walk(route.dependant)
            if getattr(d.call, "_is_permission_guard", False)
        }
        if Scope.PROJECT in scopes:
            found |= {(method, route.path) for method in route.methods}
    assert found - covered == set(), "project-scoped routes missing IDOR coverage"


def test_every_guard_declares_a_scope() -> None:
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        guards = [
            d.call for d in _walk(route.dependant) if getattr(d.call, "_is_permission_guard", False)
        ]
        for g in guards:
            assert getattr(g, "_scope", None) in set(Scope), (route.path, route.methods)


# ------------------------------------------------- mixed projects & roles


def test_run_cannot_mix_resources_from_different_projects(world) -> None:
    admin, a, b = world["admin"], world["a"], world["b"]

    def run(**overrides):
        body = {
            "playbook_id": a["playbook"],
            "inventory_id": a["inventory"],
            "credential_id": a["credential"],
            **overrides,
        }
        return admin.post("/api/runs", json=body)

    for field, value, label in (
        ("inventory_id", b["inventory"], "Inventory"),
        ("credential_id", b["credential"], "Credential"),
        ("vault_password_id", b["vault"], "Vault password"),
    ):
        response = run(**{field: value})
        assert response.status_code == 400, (field, response.text)
        assert "same project" in response.json()["detail"]
        assert label in response.json()["detail"]

    ok = run(vault_password_id=a["vault"])
    assert ok.status_code == 201
    _wait_for_completion(admin, ok.json()["id"])


def test_run_referencing_an_invisible_project_is_a_404(world) -> None:
    admin, a, b = world["admin"], world["a"], world["b"]
    only_a = _member(admin, "only-a", {a["project"]: "operator"})
    base = {
        "playbook_id": a["playbook"],
        "inventory_id": a["inventory"],
        "credential_id": a["credential"],
    }
    assert (
        only_a.post("/api/runs", json={**base, "inventory_id": b["inventory"]}).status_code == 404
    )
    assert (
        only_a.post("/api/runs", json={**base, "credential_id": b["credential"]}).status_code == 404
    )
    assert only_a.post("/api/runs", json={**base, "playbook_id": b["playbook"]}).status_code == 404


def test_roles_are_per_project(world) -> None:
    admin, a, b = world["admin"], world["a"], world["b"]
    user = _member(admin, "mixed", {a["project"]: "operator", b["project"]: "viewer"})

    made = user.post(
        "/api/playbooks", json={"name": "in-a", "content": PLAYBOOK, "project_id": a["project"]}
    )
    assert made.status_code == 201
    denied = user.post(
        "/api/playbooks", json={"name": "in-b", "content": PLAYBOOK, "project_id": b["project"]}
    )
    assert denied.status_code == 403
    assert user.get(f"/api/playbooks/{b['playbook']}").status_code == 200  # can read B
    assert (
        user.put(f"/api/playbooks/{b['playbook']}", json={"name": "x"}).status_code == 403
    )  # not write

    trigger_b = user.post(
        "/api/runs",
        json={
            "playbook_id": b["playbook"],
            "inventory_id": b["inventory"],
            "credential_id": b["credential"],
        },
    )
    assert trigger_b.status_code == 403
    trigger_a = user.post(
        "/api/runs",
        json={
            "playbook_id": a["playbook"],
            "inventory_id": a["inventory"],
            "credential_id": a["credential"],
        },
    )
    assert trigger_a.status_code == 201
    _wait_for_completion(admin, trigger_a.json()["id"])

    # extra_vars visibility follows the role in the RUN'S project
    assert user.get(f"/api/runs/{a['run']}").json()["extra_vars"] == {"greeting": "hello-a"}
    assert user.get(f"/api/runs/{b['run']}").json()["extra_vars"] == {"greeting": "[HIDDEN]"}

    # credentials of B are listable only where the role allows (viewer in B: no)
    creds = {c["id"] for c in user.get("/api/credentials").json()}
    assert creds == {a["credential"]}


def test_create_requires_project_id_when_several_are_writable(world) -> None:
    admin, a, b = world["admin"], world["a"], world["b"]
    user = _member(admin, "two-projects", {a["project"]: "operator", b["project"]: "operator"})
    response = user.post("/api/playbooks", json={"name": "ambiguous", "content": PLAYBOOK})
    assert response.status_code == 400
    assert "project_id" in response.json()["detail"]


def test_user_with_no_memberships_has_no_access(world) -> None:
    admin = world["admin"]
    nobody = make_user_client("nobody", "operator", default_membership=False)
    for path in ("/api/playbooks", "/api/inventories", "/api/credentials", "/api/runs"):
        assert nobody.get(path).status_code == 403, path
    me = nobody.get("/api/auth/me").json()
    assert me["projects"] == [] and me["permissions"] == []
    assert admin.get("/api/users").status_code == 200


def test_me_lists_project_access(world) -> None:
    admin, a, b = world["admin"], world["a"], world["b"]
    user = _member(admin, "mixed", {a["project"]: "operator", b["project"]: "viewer"})
    me = user.get("/api/auth/me").json()
    projects = {p["name"]: p for p in me["projects"]}
    assert projects["Team A"]["role"] == "operator" and projects["Team B"]["role"] == "viewer"
    assert "runs:trigger" in projects["Team A"]["permissions"]
    assert "runs:trigger" not in projects["Team B"]["permissions"]
    assert "runs:trigger" in me["permissions"]  # union across projects
    admin_me = admin.get("/api/auth/me").json()
    assert {p["name"] for p in admin_me["projects"]} >= {"Default", "Team A", "Team B"}
    assert "users:manage" in admin_me["permissions"]
    assert "users:manage" not in projects["Team A"]["permissions"]  # never project-scoped


def test_run_engine_rejects_a_credential_from_another_project(world) -> None:
    from app.models import Credential, Run
    from app.run_engine import _assert_same_project

    a, b = world["a"], world["b"]
    db = get_sessionmaker()()
    try:
        run = db.get(Run, a["run"])
        _assert_same_project(run, db.get(Credential, a["credential"]), "credential")
        with pytest.raises(RuntimeError, match="not in the run's project"):
            _assert_same_project(run, db.get(Credential, b["credential"]), "credential")
    finally:
        db.close()


# --------------------------------------------------------- projects API


def test_only_global_admin_creates_renames_and_deletes_projects(world) -> None:
    admin, a = world["admin"], world["a"]
    project_admin = _member(admin, "a-admin", {a["project"]: "admin"})
    assert project_admin.post("/api/projects", json={"name": "Nope"}).status_code == 403
    assert (
        project_admin.patch(f"/api/projects/{a['project']}", json={"name": "X"}).status_code == 403
    )
    assert project_admin.delete(f"/api/projects/{a['project']}").status_code == 403

    assert admin.post("/api/projects", json={"name": "Team A"}).status_code == 400  # duplicate
    renamed = admin.patch(f"/api/projects/{a['project']}", json={"name": "Team A2"})
    assert renamed.status_code == 200 and renamed.json()["name"] == "Team A2"


def test_project_list_shows_only_your_projects_with_your_role(world) -> None:
    admin, a, b = world["admin"], world["a"], world["b"]
    user = _member(admin, "a-viewer", {a["project"]: "viewer"})
    listed = user.get("/api/projects").json()
    assert [(p["name"], p["my_role"]) for p in listed] == [("Team A", "viewer")]
    all_names = {p["name"] for p in admin.get("/api/projects").json()}
    assert all_names >= {"Default", "Team A", "Team B"}
    assert b["project"] not in {p["id"] for p in listed}


def test_project_delete_is_blocked_while_it_has_resources(world) -> None:
    admin, a = world["admin"], world["a"]
    blocked = admin.delete(f"/api/projects/{a['project']}")
    assert blocked.status_code == 409
    assert "playbooks" in blocked.json()["detail"]


def test_deleting_an_empty_project_removes_its_run_history_and_logs(world, tmp_path) -> None:
    admin, a = world["admin"], world["a"]
    log = tmp_path / "runs" / f"{a['run']}.jsonl"
    assert log.exists()

    assert admin.delete(f"/api/playbooks/{a['playbook']}").status_code == 204
    assert admin.delete(f"/api/inventories/{a['inventory']}").status_code == 204
    assert admin.delete(f"/api/credentials/{a['credential']}").status_code == 204
    assert admin.delete(f"/api/vault-passwords/{a['vault']}").status_code == 204
    assert admin.delete(f"/api/projects/{a['project']}").status_code == 204

    assert admin.get(f"/api/runs/{a['run']}").status_code == 404
    assert not log.exists()
    assert a["project"] not in {p["id"] for p in admin.get("/api/projects").json()}


def test_project_admin_manages_only_their_own_projects_members(world) -> None:
    admin, a, b = world["admin"], world["a"], world["b"]
    boss = _member(admin, "a-boss", {a["project"]: "admin"})
    make_user_client("newcomer", "viewer", default_membership=False)
    newcomer = _user_id(admin, "newcomer")
    boss_id = _user_id(admin, "a-boss")

    assert (
        boss.put(
            f"/api/projects/{a['project']}/members/{newcomer}", json={"role": "operator"}
        ).status_code
        == 200
    )
    members = {
        m["username"]: m["role"] for m in boss.get(f"/api/projects/{a['project']}/members").json()
    }
    assert members["newcomer"] == "operator"
    assert (
        boss.put(
            f"/api/projects/{a['project']}/members/{newcomer}", json={"role": "viewer"}
        ).status_code
        == 200
    )
    assert boss.delete(f"/api/projects/{a['project']}/members/{newcomer}").status_code == 204
    assert boss.delete(f"/api/projects/{a['project']}/members/{newcomer}").status_code == 404

    # own membership is off-limits; other projects don't exist for them
    assert (
        boss.put(
            f"/api/projects/{a['project']}/members/{boss_id}", json={"role": "viewer"}
        ).status_code
        == 400
    )
    assert boss.delete(f"/api/projects/{a['project']}/members/{boss_id}").status_code == 400
    assert boss.get(f"/api/projects/{b['project']}/members").status_code == 404
    assert (
        boss.put(
            f"/api/projects/{b['project']}/members/{newcomer}", json={"role": "viewer"}
        ).status_code
        == 404
    )
    assert (
        boss.put(f"/api/projects/{a['project']}/members/99999", json={"role": "viewer"}).status_code
        == 404
    )

    # operators can't manage members at all
    op = _member(admin, "a-op", {a["project"]: "operator"})
    assert op.get(f"/api/projects/{a['project']}/members").status_code == 403
    assert (
        op.put(
            f"/api/projects/{a['project']}/members/{newcomer}", json={"role": "viewer"}
        ).status_code
        == 403
    )


def test_global_admin_can_manage_any_membership_including_their_own(world) -> None:
    admin, a = world["admin"], world["a"]
    admin_id = _user_id(admin, "admin")
    response = admin.put(
        f"/api/projects/{a['project']}/members/{admin_id}", json={"role": "viewer"}
    )
    assert response.status_code == 200


def test_deleting_a_user_removes_their_memberships(world) -> None:
    admin, a = world["admin"], world["a"]
    _member(admin, "leaver", {a["project"]: "operator"})
    uid = _user_id(admin, "leaver")
    assert admin.delete(f"/api/users/{uid}").status_code == 204
    assert uid not in {
        m["user_id"] for m in admin.get(f"/api/projects/{a['project']}/members").json()
    }


def test_new_users_are_added_to_the_only_project_or_the_named_one(client: TestClient) -> None:
    admin = _admin(client)
    body = {"username": "auto-member", "password": "a-decent-long-password"}
    assert admin.post("/api/users", json={**body, "role": "operator"}).status_code == 201
    default_id = admin.get("/api/projects").json()[0]["id"]
    members = {
        m["username"]: m["role"] for m in admin.get(f"/api/projects/{default_id}/members").json()
    }
    assert members["auto-member"] == "operator"

    other = _project(admin, "Second")  # now ambiguous: no automatic membership
    assert admin.post("/api/users", json={**body, "username": "floating"}).status_code == 201
    members = {m["username"] for m in admin.get(f"/api/projects/{default_id}/members").json()}
    assert "floating" not in members

    explicit = admin.post("/api/users", json={**body, "username": "explicit", "project_id": other})
    assert explicit.status_code == 201
    assert "explicit" in {m["username"] for m in admin.get(f"/api/projects/{other}/members").json()}
    assert (
        admin.post("/api/users", json={**body, "username": "bad", "project_id": 999}).status_code
        == 400
    )


def test_project_events_are_audited_with_project_id(world) -> None:
    admin, a = world["admin"], world["a"]
    uid = _user_id(admin, "admin")
    admin.put(f"/api/projects/{a['project']}/members/{uid}", json={"role": "operator"})
    admin.put(f"/api/projects/{a['project']}/members/{uid}", json={"role": "viewer"})
    admin.delete(f"/api/projects/{a['project']}/members/{uid}")
    events = admin.get("/api/audit", params={"limit": 200, "action": "project."}).json()["items"]
    actions = {e["action"] for e in events}
    assert {
        "project.create",
        "project.member_add",
        "project.member_role_change",
        "project.member_remove",
    } <= actions
    assert all(e["outcome"] == "success" for e in events)


def test_permission_denials_record_the_project(world) -> None:
    admin, a, b = world["admin"], world["a"], world["b"]
    # operator in B (passes the coarse guard) but only a viewer in A
    user = _member(admin, "mixed", {a["project"]: "viewer", b["project"]: "operator"})
    assert user.put(f"/api/playbooks/{a['playbook']}", json={"name": "x"}).status_code == 403
    denied = admin.get("/api/audit", params={"outcome": "denied", "limit": 50}).json()["items"]
    mine = [e for e in denied if e["actor_username"] == "mixed"]
    assert mine and all(e["project_id"] == a["project"] for e in mine)


# ------------------------------------------------------------- migration


OLD_SCHEMA = """
CREATE TABLE users (
  id INTEGER PRIMARY KEY, username VARCHAR(150) UNIQUE, password_hash VARCHAR(255),
  role VARCHAR(20) NOT NULL DEFAULT 'viewer', is_active BOOLEAN NOT NULL DEFAULT 1,
  session_version INTEGER NOT NULL DEFAULT 0, created_by VARCHAR(150),
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE playbooks (
  id INTEGER PRIMARY KEY, name VARCHAR(255),
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE inventories (
  id INTEGER PRIMARY KEY, name VARCHAR(255) UNIQUE, description VARCHAR(500),
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE credentials (
  id INTEGER PRIMARY KEY, name VARCHAR(150) UNIQUE, description VARCHAR(500),
  encrypted_private_key BLOB, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE vault_passwords (
  id INTEGER PRIMARY KEY, name VARCHAR(150) UNIQUE, description VARCHAR(500),
  encrypted_password BLOB, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE runs (
  id INTEGER PRIMARY KEY, playbook_id INTEGER, playbook_name VARCHAR(255) NOT NULL,
  inventory_id INTEGER, inventory_name VARCHAR(255) NOT NULL, group_id INTEGER,
  group_name VARCHAR(255), credential_id INTEGER, credential_name VARCHAR(150) NOT NULL,
  become BOOLEAN, status VARCHAR(20), triggered_by VARCHAR(150) NOT NULL, return_code INTEGER,
  started_at DATETIME, finished_at DATETIME, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE audit_events (
  id INTEGER PRIMARY KEY, created_at DATETIME, actor_user_id INTEGER,
  actor_username VARCHAR(150), action VARCHAR(64), target_type VARCHAR(50), target_id INTEGER,
  target_name VARCHAR(255), outcome VARCHAR(20), ip VARCHAR(64), detail JSON);
"""

OLD_ROWS = [
    "INSERT INTO playbooks (id, name) VALUES (1, 'old-playbook')",
    "INSERT INTO inventories (id, name) VALUES (1, 'old-inv')",
    "INSERT INTO credentials (id, name, encrypted_private_key) VALUES (1, 'old-cred', x'00')",
    "INSERT INTO vault_passwords (id, name, encrypted_password) VALUES (1, 'old-vault', x'00')",
    "INSERT INTO runs (id, playbook_id, playbook_name, inventory_id, inventory_name,"
    " credential_id, credential_name, become, status, triggered_by)"
    " VALUES (1, 1, 'old-playbook', 1, 'old-inv', 1, 'old-cred', 0, 'success', 'boss')",
    "INSERT INTO audit_events (id, action, outcome) VALUES (1, 'auth.login', 'success')",
]


@pytest.fixture
def old_db(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    for cache in (get_settings, get_engine, get_sessionmaker):
        cache.cache_clear()
    con = sqlite3.connect(tmp_path / "ansideck.db")
    con.executescript(OLD_SCHEMA)
    con.executemany(
        "INSERT INTO users (id, username, password_hash, role) VALUES (?,?,?,?)",
        [
            (1, "boss", hash_password("boss-password-123"), "admin"),
            (2, "op", hash_password("op-password-12345"), "operator"),
            (3, "view", hash_password("view-password-123"), "viewer"),
        ],
    )
    for statement in OLD_ROWS:
        con.execute(statement)
    con.commit()
    con.close()
    yield tmp_path
    for cache in (get_engine, get_sessionmaker, get_settings):
        cache.cache_clear()


def test_upgrade_creates_default_project_and_backfills_everything(old_db) -> None:
    init_db()
    init_db()  # a second boot changes nothing

    con = sqlite3.connect(old_db / "ansideck.db")
    con.execute("PRAGMA foreign_keys=ON")
    projects = con.execute("SELECT id, name FROM projects").fetchall()
    assert [name for _, name in projects] == ["Default"]
    default_id = projects[0][0]

    for table in ("playbooks", "inventories", "credentials", "vault_passwords", "runs"):
        ids = {r[0] for r in con.execute(f"SELECT project_id FROM {table}")}
        assert ids == {default_id}, table

    members = con.execute(
        "SELECT u.username, m.role FROM project_members m JOIN users u ON u.id=m.user_id ORDER BY 1"
    ).fetchall()
    assert members == [("op", "operator"), ("view", "viewer")]  # the global admin needs none
    assert (
        con.execute("PRAGMA user_version").scalar()
        if False
        else con.execute("PRAGMA user_version").fetchone()[0] == 1
    )
    assert con.execute("SELECT project_id FROM audit_events").fetchone() == (None,)

    # the FK really is enforced on the migrated column
    with pytest.raises(sqlite3.IntegrityError):
        con.execute("DELETE FROM projects WHERE id = ?", (default_id,))
    con.close()


def test_upgraded_users_keep_working_access(old_db) -> None:
    init_db()
    upgraded = TestClient(app)
    assert (
        upgraded.post(
            "/api/auth/login", json={"username": "op", "password": "op-password-12345"}
        ).status_code
        == 200
    )
    assert [p["name"] for p in upgraded.get("/api/auth/me").json()["projects"]] == ["Default"]
    assert [p["name"] for p in upgraded.get("/api/playbooks").json()] == ["old-playbook"]
    assert upgraded.get("/api/users").status_code == 403

    boss = TestClient(app)
    assert (
        boss.post(
            "/api/auth/login", json={"username": "boss", "password": "boss-password-123"}
        ).status_code
        == 200
    )
    assert [r["id"] for r in boss.get("/api/runs").json()] == [1]


def test_backfill_does_not_resurrect_a_deleted_default_project(old_db) -> None:
    init_db()
    con = sqlite3.connect(old_db / "ansideck.db")
    con.execute("PRAGMA foreign_keys=ON")
    for table in ("playbooks", "inventories", "credentials", "vault_passwords", "runs"):
        con.execute(f"DELETE FROM {table}")
    con.execute("DELETE FROM projects")
    con.commit()
    con.close()

    init_db()  # next boot must NOT recreate Default
    con = sqlite3.connect(old_db / "ansideck.db")
    assert con.execute("SELECT count(*) FROM projects").fetchone()[0] == 0
    con.close()


def test_fresh_install_gets_an_empty_default_project(client: TestClient) -> None:
    admin = _admin(client)
    assert [p["name"] for p in admin.get("/api/projects").json()] == ["Default"]
    # and the single-project flow needs no project_id anywhere
    assert admin.post("/api/playbooks", json={"name": "p", "content": PLAYBOOK}).status_code == 201


def test_permission_enum_has_the_new_project_permissions() -> None:
    assert Permission.MEMBERS_MANAGE.value == "members:manage"
    assert Permission.PROJECTS_MANAGE.value == "projects:manage"
