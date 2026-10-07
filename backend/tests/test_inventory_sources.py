"""Dynamic inventory sources (Phase 4G-2): plugin configs refreshed by a real worker running
real ansible-inventory, snapshots normalised as untrusted data, runs that use them."""

import json
import re
import time

from fastapi.testclient import TestClient
from sqlalchemy import select, update

from app.db import get_sessionmaker
from app.models import (
    AuditEvent,
    Inventory,
    InventoryRefresh,
    InventorySnapshot,
    NotificationAlert,
)
from app.storage import run_log_path
from app.worker.runner import refresh_error
from tests.conftest import start_worker
from tests.test_runs import _create_credential, _create_playbook, _login, _wait_for_completion

GENERATOR = """\
plugin: ansible.builtin.generator
hosts:
  name: "gen-{{ n }}"
layers:
  n: ["a", "b"]
"""

CONSTRUCTED = """\
plugin: ansible.builtin.constructed
strict: false
keyed_groups:
  - key: role
    prefix: role
compose:
  composed: "'from-' ~ role"
  owner: "'a source'"
"""


def _inventory(client: TestClient, name: str = "dyn") -> int:
    inventory_id = client.post("/api/inventories", json={"name": name}).json()["id"]
    for hostname, role in (("web1", "web"), ("db1", "db")):
        response = client.post(
            f"/api/inventories/{inventory_id}/hosts",
            json={
                "hostname": hostname,
                "vars": {"role": role, "ansible_connection": "local", "owner": "the inventory"},
            },
        )
        assert response.status_code == 201, response.text
    return inventory_id


def _add_source(client, inventory_id, name, config, **extra):
    response = client.post(
        f"/api/inventories/{inventory_id}/sources", json={"name": name, "config": config, **extra}
    )
    assert response.status_code == 201, response.text
    return response.json()


def _wait_refresh(client, inventory_id, timeout: float = 30.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        refreshes = client.get(f"/api/inventories/{inventory_id}/refreshes").json()
        if refreshes and refreshes[0]["status"] not in ("queued", "running"):
            return refreshes[0]
        time.sleep(0.2)
    raise AssertionError(f"no refresh finished: {refreshes}")


def test_sources_are_refreshed_by_a_worker_and_runs_use_them(client: TestClient) -> None:
    _login(client)
    inventory_id = _inventory(client)
    _add_source(client, inventory_id, "gen", GENERATOR)
    _add_source(client, inventory_id, "groups", CONSTRUCTED)
    refresh = _wait_refresh(client, inventory_id)
    assert refresh["status"] == "success", refresh
    assert refresh["trigger"] == "sources_changed"

    snapshot = client.get(f"/api/inventories/{inventory_id}/snapshot").json()
    groups = {g["name"]: g["hosts"] for g in snapshot["groups"]}
    assert groups == {"role_db": 1, "role_web": 1}
    assert snapshot["host_count"] == 4  # gen-a, gen-b and the two static hosts

    targets = client.get(f"/api/inventories/{inventory_id}/targets").json()
    assert {g["name"]: g["origin"] for g in targets["groups"]} == {
        "role_db": "source",
        "role_web": "source",
    }
    hosts = client.get(f"/api/inventories/{inventory_id}/hosts?q=web").json()
    assert hosts["total"] == 1
    web1 = hosts["hosts"][0]
    assert web1["origin"] == "both" and web1["groups"] == ["role_web"]
    assert web1["vars"]["composed"] == "from-web"
    # The source changed `owner` (the inventory's value wins); `role` came back unchanged.
    assert web1["overridden"] == ["owner"] and web1["vars"]["owner"] == "the inventory"

    playbook_id = _create_playbook(
        client,
        "- hosts: role_web\n  gather_facts: false\n  tasks:\n"
        '    - ansible.builtin.debug:\n        msg: "{{ composed }}"\n',
    )
    run = client.post(
        "/api/runs",
        json={
            "playbook_id": playbook_id,
            "inventory_id": inventory_id,
            "group_name": "role_web",
            "credential_id": _create_credential(client),
        },
    )
    assert run.status_code == 201, run.text
    done = _wait_for_completion(client, run.json()["id"])
    assert done["status"] == "success" and done["hosts_total"] == 1, done


def _env_credential(client, env: dict, name: str = "plugin-env") -> int:
    response = client.post("/api/credentials", json={"name": name, "kind": "env", "env": env})
    assert response.status_code == 201, response.text
    return response.json()["id"]


def test_a_broken_source_fails_the_refresh_and_alerts_once(client: TestClient) -> None:
    _login(client)
    inventory_id = _inventory(client)
    _add_source(client, inventory_id, "gen", GENERATOR)
    assert _wait_refresh(client, inventory_id)["status"] == "success"

    token = _env_credential(client, {"NETBOX_TOKEN": "nb-sentinel-token-123"})
    broken = _add_source(
        client,
        inventory_id,
        "netbox",
        "plugin: netbox.netbox.nb_inventory\napi_endpoint: http://127.0.0.1:1\n"
        "token: \"{{ lookup('env', 'NETBOX_TOKEN') }}\"\n",
        credential_id=token,
    )
    failed = _wait_refresh(client, inventory_id)
    assert failed["status"] == "failed"
    # names the source's file and the plugin's own reason
    assert re.match(rf"\d\d-src{broken['id']}\.nb_inventory\.yml: .*refused", failed["error"])
    assert "Completely failed" not in failed["error"]
    assert "nb-sentinel-token-123" not in failed["error"]
    # Runs keep using the last good snapshot.
    targets = client.get(f"/api/inventories/{inventory_id}/targets").json()
    assert targets["hosts"] == 4 and targets["last_refresh"]["status"] == "failed"

    client.post(f"/api/inventories/{inventory_id}/refresh")
    assert _wait_refresh(client, inventory_id)["status"] == "failed"
    db = get_sessionmaker()()
    alerts = db.scalars(
        select(NotificationAlert.key).where(NotificationAlert.key.like("inventory.%"))
    ).all()
    audits = db.scalars(select(AuditEvent).where(AuditEvent.action == "inventory.refresh")).all()
    db.close()
    assert alerts == [f"inventory.refresh_failed:{inventory_id}"]
    assert len(audits) == 1  # once per failure streak

    client.patch(f"/api/inventories/{inventory_id}/sources/{broken['id']}", json={"enabled": False})
    assert _wait_refresh(client, inventory_id)["status"] == "success"
    db = get_sessionmaker()()
    cleared = select(NotificationAlert.key).where(NotificationAlert.key.like("inventory.%"))
    assert db.scalars(cleared).all() == []  # the all-clear
    db.close()


def test_credential_values_are_scrubbed_from_the_snapshot(client: TestClient) -> None:
    _login(client)
    inventory_id = _inventory(client)
    credential = _env_credential(client, {"LEAKY_TOKEN": "leaky-sentinel-value-42"})
    _add_source(
        client,
        inventory_id,
        "leak",
        "plugin: ansible.builtin.constructed\nstrict: false\n"
        "compose:\n  leaked: \"lookup('env', 'LEAKY_TOKEN')\"\n",
        credential_id=credential,
    )
    refresh = _wait_refresh(client, inventory_id)
    assert refresh["status"] == "success", refresh
    snapshot = client.get(f"/api/inventories/{inventory_id}/snapshot").json()
    assert any("redacted" in w for w in snapshot["warnings"])
    hosts = client.get(f"/api/inventories/{inventory_id}/hosts").json()["hosts"]
    assert all(h["vars"]["leaked"] == "[REDACTED]" for h in hosts)
    db = get_sessionmaker()()
    for (data,) in db.execute(select(InventorySnapshot.data)):
        assert "leaky-sentinel-value-42" not in json.dumps(data)
    db.close()


def test_a_template_in_a_static_host_var_is_never_evaluated_in_a_refresh(
    client: TestClient,
) -> None:
    """Whoever edits hosts (operators) must not reach the sources' credentials, which only the
    refresh holds, through a constructed source that reads their vars."""
    _login(client)
    inventory_id = _inventory(client)
    credential = _env_credential(client, {"PLANTED_TOKEN": "planted-sentinel-value-7"})
    reads_vars = CONSTRUCTED + "  piped: owner\n  nested: deep.list[0]\n"
    _add_source(client, inventory_id, "groups", reads_vars, credential_id=credential)
    assert _wait_refresh(client, inventory_id)["status"] == "success"

    host = client.get(f"/api/inventories/{inventory_id}").json()["hosts"][0]
    planted = {
        "role": "{{ lookup('env', 'PLANTED_TOKEN') | b64encode }}",
        "owner": "{{ lookup('pipe', 'echo piped-$((6*7))') }}",
        "deep": {"list": ["{{ lookup('env', 'PLANTED_TOKEN') | reverse }}"]},
    }
    response = client.put(
        f"/api/inventories/{inventory_id}/hosts/{host['id']}",
        json={"hostname": host["hostname"], "vars": planted},
    )
    assert response.status_code == 200, response.text
    refresh = _wait_refresh(client, inventory_id)
    assert refresh["status"] == "success" and refresh["trigger"] == "static_changed", refresh

    db = get_sessionmaker()()
    data = json.dumps(db.scalars(select(InventorySnapshot.data)).all())
    db.close()
    for evaluated in ("cGxhbnRlZC1zZW50aW5lbC12YWx1ZS03", "7-eulav", "piped-42"):
        assert evaluated not in data
    hosts = client.get(f"/api/inventories/{inventory_id}/hosts?q={host['hostname']}").json()
    assert hosts["hosts"][0]["vars"]["composed"] == "from-" + planted["role"]  # just text


def test_a_template_from_a_source_is_never_evaluated_in_a_run(client: TestClient) -> None:
    _login(client)
    inventory_id = _inventory(client)
    _add_source(
        client,
        inventory_id,
        "tmpl",
        "plugin: ansible.builtin.constructed\nstrict: false\n"
        "compose:\n  from_source: \"'{{ 6 * 7 }}'\"\n",
    )
    assert _wait_refresh(client, inventory_id)["status"] == "success"
    playbook_id = _create_playbook(
        client,
        "- hosts: web1\n  gather_facts: false\n  tasks:\n"
        "    - ansible.builtin.debug:\n        var: from_source\n",
    )
    run = client.post(
        "/api/runs",
        json={
            "playbook_id": playbook_id,
            "inventory_id": inventory_id,
            "credential_id": _create_credential(client),
        },
    ).json()
    done = _wait_for_completion(client, run["id"])
    assert done["status"] == "success", done
    log = run_log_path(run["id"]).read_text()
    assert "{{ 6 * 7 }}" in log and '"from_source": "42"' not in log


def test_a_refresh_that_overruns_is_stopped(client: TestClient) -> None:
    _login(client)
    inventory_id = _inventory(client)
    db = get_sessionmaker()()
    db.execute(update(Inventory).values(refresh_interval_seconds=0))
    db.commit()
    db.close()
    client.worker.stop()  # so the refresh waits while its timeout is shortened
    _add_source(
        client,
        inventory_id,
        "slow",
        "plugin: ansible.builtin.constructed\nstrict: true\n"
        "compose:\n  slow: \"lookup('pipe', 'sleep 30')\"\n",
    )
    db = get_sessionmaker()()
    db.execute(update(InventoryRefresh).values(timeout_seconds=2))
    db.commit()
    db.close()
    client.worker = start_worker(client.worker.galaxy_dir, heartbeat_seconds=0.3)
    try:
        refresh = _wait_refresh(client, inventory_id, timeout=40)
    finally:
        client.worker.stop()
    assert refresh["status"] == "timed_out", refresh
    assert refresh["error"].startswith("timed out after")


def test_a_failed_refresh_says_which_source_failed_and_why() -> None:
    stderr = (
        "[WARNING]: Failed to parse inventory with 'auto' plugin: pytz must be installed\n"
        "Failed to parse inventory with 'auto' plugin.\n"
        "[WARNING]: Failed to parse inventory with 'yaml' plugin: Plugin configuration YAML "
        "file, not YAML inventory\n"
        "[ERROR]: Completely failed to parse inventory source "
        "/tmp/ansideck-refresh-4-ab12/inventory/10-src1.nb_inventory.yml\n"
        "[WARNING]: Failed to parse inventory with 'auto' plugin: token sekret-123 refused\n"
        "[ERROR]: Completely failed to parse inventory source "
        "/tmp/ansideck-refresh-4-ab12/inventory/11-src2.nb_inventory.yml\n"
    )
    assert refresh_error(stderr, ["sekret-123"], 1) == (
        "10-src1.nb_inventory.yml: pytz must be installed\n"
        "11-src2.nb_inventory.yml: token [REDACTED] refused"
    )
    assert refresh_error("", [], 3) == "ansible-inventory failed (exit code 3)"
