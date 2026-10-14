"""API key limits: the addresses a key may be used from, and the playbooks and inventories it
may start runs of (directly or through a template); editing them, rotation and the audit."""

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db import get_sessionmaker
from app.main import app
from app.models import AuditEvent
from tests.test_api_keys import _create_key, _run_body, world

__all__ = ["world"]


def _key_client(token: str, ip: str = "203.0.113.7") -> TestClient:
    return TestClient(app, headers={"Authorization": f"Bearer {token}"}, client=(ip, 50000))


def _audit(action: str) -> list[AuditEvent]:
    with get_sessionmaker()() as db:
        return list(db.scalars(select(AuditEvent).where(AuditEvent.action == action)))


def test_a_key_works_only_from_its_networks(world) -> None:
    a = world["a"]
    created = _create_key(
        world["admin"],
        a["project"],
        allowed_networks=["203.0.113.0/24", "2001:db8::1", "203.0.113.9"],
    )
    assert created["allowed_networks"] == ["203.0.113.0/24", "2001:db8::1/128", "203.0.113.9/32"]
    token = created["token"]
    assert _key_client(token).get(f"/api/runs/{a['run']}").status_code == 200
    assert _key_client(token, "::ffff:203.0.113.8").get("/api/runs").status_code == 200
    refused = _key_client(token, "198.51.100.1").get("/api/runs")
    assert refused.status_code == 401 and refused.json()["detail"] == "Invalid API key"
    [failure] = [e for e in _audit("apikey.auth") if e.outcome == "failure"]
    assert failure.detail == {"reason": "address not allowed"}

    bad = world["admin"].post(
        f"/api/projects/{a['project']}/api-keys",
        json={"name": "x", "preset": "trigger", "current_password": "admin",
              "allowed_networks": ["not-a-network"]},
    )  # fmt: skip
    assert bad.status_code == 422 and "not an IP address or CIDR" in bad.text


def test_a_key_starts_runs_of_its_playbooks_and_inventories_only(world) -> None:
    a, admin = world["a"], world["admin"]
    # Only the project's own playbooks and inventories.
    refused = admin.post(
        f"/api/projects/{a['project']}/api-keys",
        json={"name": "x", "preset": "trigger", "current_password": "admin",
              "allowed_inventory_ids": [world["b"]["inventory"]]},
    )  # fmt: skip
    assert refused.status_code == 422 and "No inventory" in refused.text

    created = _create_key(admin, a["project"], allowed_playbook_ids=[a["playbook"]])
    assert [p["id"] for p in created["allowed_playbooks"]] == [a["playbook"]]
    assert created["allowed_inventories"] is None
    key = _key_client(created["token"])
    assert key.post("/api/runs", json=_run_body(a)).status_code == 201

    other_playbook = admin.post(
        "/api/playbooks",
        json={"name": "other.yml", "content": "- hosts: all\n  tasks: []\n",
              "project_id": a["project"]},
    ).json()["id"]  # fmt: skip
    denied = key.post("/api/runs", json=_run_body(a, playbook_id=other_playbook))
    assert denied.status_code == 403 and denied.json()["detail"] == (
        "This API key may not run this playbook"
    )
    [event] = [e for e in _audit("permission.denied") if e.actor_username == "apikey:ci"]
    assert event.detail["reason"] == "This API key may not run this playbook"

    # Through a template it's the same check.
    template = admin.post(
        "/api/run-templates", json={"name": "t", **_run_body(a, playbook_id=other_playbook)}
    ).json()
    assert key.post(f"/api/run-templates/{template['id']}/launch").status_code == 403

    # Editing the limits takes effect at once and keeps the token; rotation keeps them.
    url = f"/api/projects/{a['project']}/api-keys/{created['id']}"
    changed = admin.patch(
        url,
        json={"allowed_playbook_ids": [a["playbook"], other_playbook],
              "allowed_inventory_ids": [a["inventory"]]},
    )  # fmt: skip
    assert changed.status_code == 200, changed.text
    assert [p["id"] for p in changed.json()["allowed_playbooks"]] == [a["playbook"], other_playbook]
    assert key.post("/api/runs", json=_run_body(a, playbook_id=other_playbook)).status_code == 201
    [update] = _audit("apikey.update")
    assert update.detail["allowed_inventory_ids"] == [a["inventory"]]
    assert update.detail["allowed_inventory_ids_before"] is None
    removed = admin.patch(url, json={"allowed_playbook_ids": []}).json()
    assert removed["allowed_playbooks"] is None
    assert [p["id"] for p in removed["allowed_inventories"]] == [a["inventory"]]

    rotated = admin.post(f"{url}/rotate", json={"current_password": "admin"}).json()
    assert [p["id"] for p in rotated["allowed_inventories"]] == [a["inventory"]]
    assert _key_client(rotated["token"]).post("/api/runs", json=_run_body(a)).status_code == 201

    # Only key managers, and only within the project.
    assert key.get("/api/runs").status_code == 401  # rotated: the old token is revoked
    rotated_url = f"/api/projects/{a['project']}/api-keys/{rotated['id']}"
    as_key = _key_client(rotated["token"]).patch(rotated_url, json={"allowed_playbook_ids": None})
    assert as_key.status_code == 403  # a key can't change keys
    elsewhere = f"/api/projects/{world['b']['project']}/api-keys/{created['id']}"
    assert admin.patch(elsewhere, json={}).status_code == 404
