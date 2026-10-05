"""Runs see the whole group tree, pinned when they are triggered (Phase 4G-1), and the
inventory's host and group names are ones ansible reads as given."""

import yaml
from fastapi.testclient import TestClient

from app.db import get_sessionmaker
from app.jobs import build_job
from app.models import InventoryGroup, InventoryHost, Run
from tests.test_runs import (
    _create_credential,
    _create_inventory_with_host,
    _create_playbook,
    _login,
    _wait_for_completion,
)

GROUP_PLAYBOOK = """\
- hosts: web
  connection: local
  gather_facts: false
  tasks:
    - name: write marker
      ansible.builtin.copy:
        content: "{{ marker_text }}"
        dest: "{{ marker_path }}"
"""


def _inventory_with_web_group(client: TestClient, marker) -> tuple[int, int, int]:
    inventory_id, host_id = _create_inventory_with_host(client, str(marker))
    group = client.post(f"/api/inventories/{inventory_id}/groups", json={"name": "web"}).json()
    client.put(
        f"/api/inventories/{inventory_id}/hosts/{host_id}",
        json={"group_ids": [group["id"]], "vars": {"marker_path": str(marker), "marker_text": "a"}},
    )
    return inventory_id, host_id, group["id"]


def _trigger(client: TestClient, playbook_id: int, inventory_id: int, **extra):
    return client.post(
        "/api/runs",
        json={
            "playbook_id": playbook_id,
            "inventory_id": inventory_id,
            "credential_id": _create_credential(client, f"key-{len(extra)}-{id(extra)}"),
            **extra,
        },
    )


def test_a_play_for_a_group_runs_on_it_without_targeting_it(client: TestClient, tmp_path) -> None:
    """Before 4G only the targeted group existed in a run's inventory: `hosts: web` with
    'All hosts' matched nothing."""
    _login(client)
    marker = tmp_path / "marker.txt"
    inventory_id, _, _ = _inventory_with_web_group(client, marker)
    run = _trigger(client, _create_playbook(client, GROUP_PLAYBOOK), inventory_id).json()
    done = _wait_for_completion(client, run["id"])
    assert done["status"] == "success" and done["hosts_total"] == 1
    assert marker.read_text() == "a"


def test_a_group_can_be_targeted_by_name(client: TestClient, tmp_path) -> None:
    _login(client)
    inventory_id, _, group_id = _inventory_with_web_group(client, tmp_path / "m")
    playbook_id = _create_playbook(client, GROUP_PLAYBOOK)
    run = _trigger(client, playbook_id, inventory_id, group_name="web")
    assert run.status_code == 201, run.text
    assert run.json()["group_name"] == "web"
    db = get_sessionmaker()()
    assert db.get(Run, run.json()["id"]).group_id == group_id  # linked, for history
    db.close()

    missing = _trigger(client, playbook_id, inventory_id, group_name="nope")
    assert missing.status_code == 400 and "No group named 'nope'" in missing.json()["detail"]
    mismatch = _trigger(client, playbook_id, inventory_id, group_id=group_id, group_name="db")
    assert mismatch.status_code == 400


def test_edits_while_a_run_waits_do_not_change_what_it_runs(client: TestClient, tmp_path) -> None:
    _login(client)
    inventory_id, host_id, _ = _inventory_with_web_group(client, tmp_path / "m")
    run_id = _trigger(client, _create_playbook(client, GROUP_PLAYBOOK), inventory_id).json()["id"]
    client.put(
        f"/api/inventories/{inventory_id}/hosts/{host_id}", json={"vars": {"marker_text": "b"}}
    )
    client.post(f"/api/inventories/{inventory_id}/hosts", json={"hostname": "late", "vars": {}})

    db = get_sessionmaker()()
    run = db.get(Run, run_id)
    job = build_job(db, run)
    assert run.inventory_sha256 is not None and len(run.inventory_sha256) == 64
    db.close()
    inventory = yaml.safe_load(job["inventory"])
    assert list(inventory["all"]["hosts"]) == ["test-host"]
    assert inventory["all"]["hosts"]["test-host"]["marker_text"] == "a"


def test_names_ansible_would_read_differently_are_refused(client: TestClient) -> None:
    _login(client)
    inventory_id = client.post("/api/inventories", json={"name": "names"}).json()["id"]
    for hostname in ("db:5432", "web[1:3]", "a b", "{{ x }}"):
        response = client.post(
            f"/api/inventories/{inventory_id}/hosts", json={"hostname": hostname, "vars": {}}
        )
        assert response.status_code == 400 and response.json()["detail"].startswith("Host name")
    for name in ("all", "ungrouped", "a:b"):
        response = client.post(f"/api/inventories/{inventory_id}/groups", json={"name": name})
        assert response.status_code == 400 and response.json()["detail"].startswith("Group name")
    host = client.post(f"/api/inventories/{inventory_id}/hosts", json={"hostname": "ok"}).json()
    renamed = client.put(
        f"/api/inventories/{inventory_id}/hosts/{host['id']}", json={"hostname": "ok:22"}
    )
    assert renamed.status_code == 400


def test_a_legacy_bad_name_must_be_fixed_before_running(client: TestClient, tmp_path) -> None:
    _login(client)
    inventory_id, _ = _create_inventory_with_host(client, str(tmp_path / "m"))
    db = get_sessionmaker()()  # rows from before names were checked
    db.add(InventoryHost(inventory_id=inventory_id, hostname="db:5432", vars={}))
    db.add(InventoryGroup(inventory_id=inventory_id, name="all"))
    db.commit()
    db.close()
    response = _trigger(client, _create_playbook(client, GROUP_PLAYBOOK), inventory_id)
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert "host 'db:5432' must not include a port" in detail and "group 'all'" in detail
