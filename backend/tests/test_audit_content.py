"""Changes to playbooks, inventories, their groups and hosts, and git sync requests are in
the audit log: who changed what, without the secrets that host vars and playbooks hold."""

import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from app.db import get_sessionmaker
from app.main import app
from app.models import AuditEvent
from tests.routes import iter_api_routes
from tests.test_git_sources import _create, make_repo

PLAY = "- hosts: all\n  gather_facts: false\n  tasks: []\n"
SECRET = "s3cret-value-never-audited"

# Every editing route of these routers, and the action it records (tested below).
AUDITED = {
    ("POST", "/api/playbooks"): "playbook.create",
    ("PUT", "/api/playbooks/{playbook_id}"): "playbook.update",
    ("DELETE", "/api/playbooks/{playbook_id}"): "playbook.delete",
    ("POST", "/api/inventories"): "inventory.create",
    ("PUT", "/api/inventories/{inventory_id}"): "inventory.update",
    ("DELETE", "/api/inventories/{inventory_id}"): "inventory.delete",
    ("POST", "/api/inventories/{inventory_id}/groups"): "inventory.group_create",
    ("PUT", "/api/inventories/{inventory_id}/groups/{group_id}"): "inventory.group_update",
    ("DELETE", "/api/inventories/{inventory_id}/groups/{group_id}"): "inventory.group_delete",
    ("POST", "/api/inventories/{inventory_id}/hosts"): "inventory.host_create",
    ("PUT", "/api/inventories/{inventory_id}/hosts/{host_id}"): "inventory.host_update",
    ("DELETE", "/api/inventories/{inventory_id}/hosts/{host_id}"): "inventory.host_delete",
}
# Editing routes that are audited elsewhere or change nothing stored.
NOT_HERE = {
    ("POST", "/api/playbooks/lint"),  # a check: stores no content
    ("POST", "/api/playbooks/{playbook_id}/lint"),
    ("PUT", "/api/inventories/{inventory_id}/refresh-settings"),  # inventory sources' router
}


def _events(action_prefix: str) -> list[AuditEvent]:
    db = get_sessionmaker()()
    try:
        return (
            db.query(AuditEvent)
            .filter(AuditEvent.action.startswith(action_prefix))
            .order_by(AuditEvent.id)
            .all()
        )
    finally:
        db.close()


def test_every_editing_route_of_these_routers_is_listed() -> None:
    """A new editing route has to say how it is audited."""
    routes = {
        (method, route.path)
        for route in iter_api_routes(app)
        for method in route.methods
        if method in ("POST", "PUT", "PATCH", "DELETE")
        and route.path.startswith(("/api/playbooks", "/api/inventories"))
        and "/sources" not in route.path  # inventory sources: audited in their own router
        and not route.path.endswith("/refresh")
    }
    assert routes == AUDITED.keys() | NOT_HERE


def test_playbook_changes_are_audited_by_content_hash_only(admin_client: TestClient) -> None:
    created = admin_client.post("/api/playbooks", json={"name": "site.yml", "content": PLAY})
    pid = created.json()["id"]
    changed = PLAY.replace("tasks: []", f"vars:\n    token: {SECRET}\n  tasks: []")
    admin_client.put(f"/api/playbooks/{pid}", json={"content": changed, "name": "deploy.yml"})
    admin_client.put(f"/api/playbooks/{pid}", json={"content": changed})  # no change: no row
    admin_client.delete(f"/api/playbooks/{pid}")

    create, update, delete = _events("playbook.")
    assert [e.action for e in (create, update, delete)] == [
        "playbook.create",
        "playbook.update",
        "playbook.delete",
    ]
    assert create.actor_username == "admin" and create.target_name == "site.yml"
    assert create.detail["sha256"] == hashlib.sha256(PLAY.encode()).hexdigest()
    assert update.target_name == "deploy.yml" and update.detail["renamed_from"] == "site.yml"
    assert update.detail["sha256_before"] == create.detail["sha256"]
    assert update.detail["sha256"] == hashlib.sha256(changed.encode()).hexdigest()
    assert delete.target_id == pid and delete.detail["sha256"] == update.detail["sha256"]
    assert all(e.project_id == 1 and e.ip for e in (create, update, delete))
    assert SECRET not in json.dumps([e.detail for e in (create, update, delete)])


def test_inventory_group_and_host_changes_are_audited_without_var_values(
    admin_client: TestClient,
) -> None:
    c = admin_client
    inv = c.post("/api/inventories", json={"name": "lab"}).json()["id"]
    c.put(f"/api/inventories/{inv}", json={"name": "lab2", "description": "x"})
    group = c.post(f"/api/inventories/{inv}/groups", json={"name": "web"}).json()["id"]
    c.put(f"/api/inventories/{inv}/groups/{group}", json={"name": "www"})
    host = c.post(
        f"/api/inventories/{inv}/hosts",
        json={"hostname": "h1", "vars": {"ansible_host": "10.0.0.1", "db_password": SECRET}},
    ).json()["id"]
    c.put(
        f"/api/inventories/{inv}/hosts/{host}",
        json={"vars": {"ansible_host": "10.0.0.2", "db_password": SECRET}, "group_ids": [group]},
    )
    c.put(f"/api/inventories/{inv}/hosts/{host}", json={"hostname": "h1"})  # no change: no row
    c.delete(f"/api/inventories/{inv}/hosts/{host}")
    c.delete(f"/api/inventories/{inv}/groups/{group}")
    c.delete(f"/api/inventories/{inv}")

    events = _events("inventory.")
    by_action = {e.action: e for e in events if e.action != "inventory.refresh_requested"}
    assert set(by_action) == set(list(AUDITED.values())[3:])
    assert by_action["inventory.update"].detail == {
        "renamed_from": "lab",
        "description_changed": True,
    }
    assert by_action["inventory.group_update"].detail == {
        "inventory": "lab2",
        "renamed_from": "web",
    }
    host_create = by_action["inventory.host_create"]
    assert host_create.target_type == "inventory_host" and host_create.target_name == "h1"
    assert host_create.detail["vars"] == ["ansible_host", "db_password"]
    assert by_action["inventory.host_update"].detail == {
        "inventory": "lab2",
        "vars_changed": ["ansible_host"],  # names of what changed, never values
        "groups": ["www"],
    }
    assert by_action["inventory.delete"].detail == {"hosts": 0, "groups": 0}
    assert all(e.project_id == 1 for e in events)
    dumped = json.dumps([e.detail for e in events])
    assert SECRET not in dumped and "10.0.0.2" not in dumped


@pytest.fixture
def git_admin(client: TestClient, monkeypatch) -> TestClient:
    from app.config import get_settings
    from tests.test_projects import _admin

    monkeypatch.setenv("GIT_ALLOW_LOCAL_SOURCES", "true")
    get_settings.cache_clear()
    yield _admin(client)
    get_settings.cache_clear()


def test_a_sync_request_records_who_asked(git_admin: TestClient, tmp_path) -> None:
    repo = make_repo(tmp_path / "repo", {"site.yml": PLAY})
    source = _create(git_admin, repo)
    response = git_admin.post(f"/api/projects/1/git-sources/{source['id']}/sync")
    assert response.status_code == 202
    (event,) = _events("git_source.sync_requested")
    assert event.actor_username == "admin" and event.target_id == source["id"]
