"""Refreshing an inventory's dynamic sources before a run: the run waits for a refresh queued
when it was started, then runs with what that refresh found, or fails with it. The inventory's
"refresh before every run" is the default; a run, a template or a launch may say otherwise."""

import itertools

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db import get_sessionmaker
from app.models import AuditEvent, InventoryRefresh, Run
from tests.conftest import internal_client
from tests.test_inventory_refresh_protocol import ClaimedRefresh, _output, _setup
from tests.test_runs import SUCCESS_PLAYBOOK, _create_credential, _create_playbook

pytestmark = pytest.mark.no_worker  # these tests play the worker themselves

_names = itertools.count()


def _refreshed(client: TestClient, hosts: dict, groups: dict | None = None) -> int:
    """Claims the queued refresh and finishes it with these hosts; returns its id."""
    claimed = ClaimedRefresh()
    assert claimed.job().status_code == 200
    assert claimed.finish(_output(hosts, groups)).status_code == 200
    return claimed.id


def _start(client: TestClient, inventory_id: int, **body) -> dict:
    n = next(_names)
    response = client.post(
        "/api/runs",
        json={
            "playbook_id": _create_playbook(client, SUCCESS_PLAYBOOK, name=f"p{n}.yml"),
            "inventory_id": inventory_id,
            "credential_id": _create_credential(client, name=f"c{n}"),
            **body,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _run(run_id: int) -> Run:
    with get_sessionmaker()() as db:
        return db.get(Run, run_id)


def _claim_run():
    return internal_client().post(
        "/internal/claim",
        json={"worker_id": "w", "wait_seconds": 0, "kinds": ["run"], "host_keys": True},
    )


def test_a_run_waits_for_its_refresh_and_runs_with_what_it_found(client) -> None:
    inventory_id = _setup(client)
    first = _refreshed(client, {"gen": {}})
    run = _start(client, inventory_id, refresh_first=True, group_name="site_a")
    assert run["refresh_first"] is True and run["inventory_snapshot_at"] is None
    row = _run(run["id"])
    assert row.waiting_refresh_id not in (None, first)
    waiting = client.get(f"/api/runs/{run['id']}").json()["waiting_reason"]
    assert waiting == "Waiting for its inventory's sources to be refreshed"
    assert _claim_run().status_code == 204  # not before the refresh ends

    # A second run asking for a refresh shares the one still queued.
    other = _start(client, inventory_id, refresh_first=True)
    assert _run(other["id"]).waiting_refresh_id == row.waiting_refresh_id

    refresh_id = _refreshed(client, {"gen": {}, "gen2": {}}, {"site_a": {"hosts": ["gen", "gen2"]}})
    assert refresh_id == row.waiting_refresh_id
    pinned = client.get(f"/api/runs/{run['id']}").json()
    assert pinned["inventory_snapshot_hosts"] == 2  # what the sources found: gen, gen2
    claim = _claim_run().json()
    assert claim["run_id"] == run["id"]
    job = (
        internal_client()
        .post(
            f"/internal/runs/{run['id']}/job",
            json={"job_token": claim["job_token"]},
            headers={"X-Claim-Token": claim["claim_token"]},
        )
        .json()
    )
    assert "gen2" in job["inventory"]
    with get_sessionmaker()() as db:
        trigger = db.scalars(
            select(AuditEvent).where(AuditEvent.action == "run.trigger").order_by(AuditEvent.id)
        ).first()
        assert trigger.detail["refresh_first"] is True
        assert db.get(InventoryRefresh, refresh_id).trigger == "run"


def test_a_run_fails_with_its_refresh_or_without_its_target_group(client) -> None:
    inventory_id = _setup(client)
    _refreshed(client, {"gen": {}}, {"site_a": {"hosts": ["gen"]}})

    failing = _start(client, inventory_id, refresh_first=True)
    claimed = ClaimedRefresh()
    claimed.job()
    claimed.post("complete", {"status": "failed", "error": "netbox: 401 Unauthorized\nmore"})
    row = _run(failing["id"])
    assert row.status == "failed"
    assert row.status_reason == "not run: the inventory refresh failed: netbox: 401 Unauthorized"

    gone = _start(client, inventory_id, refresh_first=True, group_name="site_a")
    _refreshed(client, {"gen": {}})  # site_a is gone
    row = _run(gone["id"])
    assert row.status == "failed"
    assert row.status_reason == (
        "not run: its target group 'site_a' is not in the refreshed inventory"
    )


def test_the_inventory_says_whether_runs_refresh_first(client) -> None:
    inventory_id = _setup(client)
    # Before any refresh worked, only a run that refreshes first can start.
    blocked = client.post(
        "/api/runs",
        json={
            "playbook_id": _create_playbook(client, SUCCESS_PLAYBOOK, name="early.yml"),
            "inventory_id": inventory_id,
            "credential_id": _create_credential(client, name="early"),
        },
    )
    assert blocked.status_code == 409
    early = _start(client, inventory_id, refresh_first=True)
    assert _run(early["id"]).waiting_refresh_id is not None
    _refreshed(client, {"gen": {}})

    url = f"/api/inventories/{inventory_id}/refresh-settings"
    settings = client.put(url, json={"refresh_before_run": True}).json()
    assert settings["refresh_before_run"] is True
    assert settings["refresh_interval_seconds"] == 0  # left as it was
    assert client.get(f"/api/inventories/{inventory_id}").json()["refresh_before_run"] is True
    assert client.get(f"/api/inventories/{inventory_id}/targets").json()["refresh_before_run"]
    with get_sessionmaker()() as db:
        event = db.scalars(
            select(AuditEvent).where(AuditEvent.action == "inventory.refresh_settings")
        ).one()
        assert event.detail == {"refresh_before_run": True}

    assert _start(client, inventory_id)["refresh_first"] is True  # the default
    assert _start(client, inventory_id, refresh_first=False)["refresh_first"] is False

    # An inventory without sources has nothing to refresh.
    plain = client.post("/api/inventories", json={"name": "plain"}).json()["id"]
    client.post(f"/api/inventories/{plain}/hosts", json={"hostname": "h1"})
    assert _start(client, plain, refresh_first=True)["refresh_first"] is False


def test_templates_and_runs_again_keep_the_choice(client) -> None:
    inventory_id = _setup(client)
    _refreshed(client, {"gen": {}})
    template = client.post(
        "/api/run-templates",
        json={
            "name": "fresh",
            "playbook_id": _create_playbook(client, SUCCESS_PLAYBOOK, name="t.yml"),
            "inventory_id": inventory_id,
            "credential_id": _create_credential(client, name="t"),
            "refresh_first": True,
        },
    )
    assert template.status_code == 201, template.text
    assert template.json()["refresh_first"] is True
    launched = client.post(f"/api/run-templates/{template.json()['id']}/launch").json()
    assert launched["refresh_first"] is True
    once = client.post(
        f"/api/run-templates/{template.json()['id']}/launch", json={"refresh_first": False}
    ).json()
    assert once["refresh_first"] is False
    again = client.post(f"/api/runs/{launched['id']}/rerun")
    assert again.status_code == 201, again.text
    assert again.json()["refresh_first"] is True
