"""Per-source schedules (app.inventory_sources): a source's own interval or its inventory's,
refreshes that run only the sources they are for (requests that merge widen them), what each
change refreshes, and the alert that stays while any source is still failing."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text, update

from app.db import get_sessionmaker
from app.inventory_sources import due_sources
from app.models import (
    InventoryRefresh,
    InventorySource,
    NotificationAlert,
    RunStatus,
)
from app.reaper import reap_once
from tests.test_inventory_refresh_protocol import ClaimedRefresh
from tests.test_inventory_sources import _add_source, _inventory, _wait_refresh
from tests.test_runs import SUCCESS_PLAYBOOK, _create_credential, _create_playbook, _login

GENERATOR = (
    "plugin: ansible.builtin.generator\nhosts:\n  name: '{{ n }}-{{ x }}'\nlayers:\n  x: [a, b]\n"
)
CONSTRUCTED = "plugin: ansible.builtin.constructed\nstrict: false\n"


def _gen(name: str) -> str:
    return GENERATOR.replace("{{ n }}", name)


def _queued(inventory_id: int) -> InventoryRefresh | None:
    db = get_sessionmaker()()
    try:
        return db.scalars(
            select(InventoryRefresh).where(
                InventoryRefresh.inventory_id == inventory_id,
                InventoryRefresh.status == RunStatus.QUEUED.value,
            )
        ).first()
    finally:
        db.close()


def _finish_all() -> None:
    """Marks every refresh done (the test plays no worker)."""
    db = get_sessionmaker()()
    db.execute(update(InventoryRefresh).values(status="success", claim_token_hash=None))
    db.commit()
    db.close()


def _setup(client: TestClient) -> tuple[int, dict, dict, dict]:
    _login(client)
    inventory_id = client.post("/api/inventories", json={"name": "dyn"}).json()["id"]
    one = _add_source(client, inventory_id, "one", _gen("one"))
    two = _add_source(client, inventory_id, "two", _gen("two"), refresh_interval_seconds=0)
    groups = _add_source(client, inventory_id, "groups", CONSTRUCTED)
    return inventory_id, one, two, groups


@pytest.mark.no_worker
def test_a_source_is_due_by_its_own_interval_or_its_inventorys(client: TestClient) -> None:
    inventory_id, one, two, _groups = _setup(client)
    client.put(
        f"/api/inventories/{inventory_id}/refresh-settings",
        json={"refresh_interval_seconds": 3600},
    )
    db = get_sessionmaker()()
    db.execute(update(InventorySource).values(last_queued_at=text("now() - interval '2 hours'")))
    db.commit()
    # one: the inventory's hour has passed; two: 0, only on changes; groups: constructed.
    assert due_sources(db) == {inventory_id: [one["id"]]}
    db.execute(
        update(InventorySource)
        .where(InventorySource.id == one["id"])
        .values(refresh_interval_seconds=86400)
    )
    db.execute(
        update(InventorySource)
        .where(InventorySource.id == two["id"])
        .values(refresh_interval_seconds=300)
    )
    db.commit()
    assert due_sources(db) == {inventory_id: [two["id"]]}
    db.execute(update(InventorySource).values(last_queued_at=None))  # never run: due now
    db.execute(update(InventorySource).where(InventorySource.id == two["id"]).values(enabled=False))
    db.commit()
    assert due_sources(db) == {inventory_id: [one["id"]]}
    db.close()

    _finish_all()
    db = get_sessionmaker()()
    db.execute(update(InventorySource).values(enabled=True, last_queued_at=None))
    db.commit()
    db.close()
    reap_once()
    assert _queued(inventory_id).scope == sorted([one["id"], two["id"]])
    db = get_sessionmaker()()
    assert due_sources(db) == {}  # queued now: not due again until their interval passes
    db.close()


@pytest.mark.no_worker
def test_requests_that_merge_widen_the_queued_refresh(client: TestClient) -> None:
    inventory_id, one, two, _groups = _setup(client)
    assert _queued(inventory_id).scope == sorted([one["id"], two["id"]])  # the two new ones
    client.post(f"/api/inventories/{inventory_id}/hosts", json={"hostname": "h", "vars": {}})
    assert _queued(inventory_id).scope == sorted([one["id"], two["id"]])  # [] adds nothing
    client.post(f"/api/inventories/{inventory_id}/refresh")
    assert _queued(inventory_id).scope is None  # Refresh now: every source
    client.post(f"/api/inventories/{inventory_id}/sources/{one['id']}/refresh")
    assert _queued(inventory_id).scope is None  # a full one stays full


@pytest.mark.no_worker
def test_each_change_refreshes_only_what_it_changes(client: TestClient) -> None:
    inventory_id, one, two, _groups = _setup(client)
    _finish_all()

    def scope_after(request) -> list[int] | str | None:
        _finish_all()
        response = request()
        assert response.status_code in (200, 201, 202, 204), response.text
        queued = _queued(inventory_id)
        return "none" if queued is None else queued.scope

    hosts = f"/api/inventories/{inventory_id}/hosts"
    sources = f"/api/inventories/{inventory_id}/sources"
    assert scope_after(lambda: client.post(hosts, json={"hostname": "s1", "vars": {}})) == []
    assert scope_after(
        lambda: client.patch(f"{sources}/{one['id']}", json={"config": _gen("uno")})
    ) == [one["id"]]
    assert (
        scope_after(lambda: client.patch(f"{sources}/{two['id']}", json={"enabled": False})) == []
    )
    assert scope_after(lambda: client.patch(f"{sources}/{two['id']}", json={"enabled": True})) == [
        two["id"]
    ]
    assert scope_after(lambda: client.patch(f"{sources}/{one['id']}", json={"position": 5})) == []
    assert (
        scope_after(lambda: client.patch(f"{sources}/{one['id']}", json={"name": "won"})) == "none"
    )
    assert (
        scope_after(
            lambda: client.patch(f"{sources}/{one['id']}", json={"refresh_interval_seconds": 900})
        )
        == "none"
    )
    assert scope_after(lambda: client.post(f"{sources}/{two['id']}/refresh")) == [two["id"]]
    assert scope_after(lambda: client.delete(f"{sources}/{two['id']}")) == []
    assert scope_after(lambda: client.post(f"/api/inventories/{inventory_id}/refresh")) is None

    # A run that refreshes first widens a queued partial refresh to every source.
    _finish_all()
    client.post(f"{sources}/{one['id']}/refresh")
    run = client.post(
        "/api/runs",
        json={
            "playbook_id": _create_playbook(client, SUCCESS_PLAYBOOK),
            "inventory_id": inventory_id,
            "credential_id": _create_credential(client),
            "refresh_first": True,
        },
    )
    assert run.status_code == 201, run.text
    assert _queued(inventory_id).scope is None
    client.patch(f"{sources}/{one['id']}", json={"enabled": False})
    assert client.post(f"{sources}/{one['id']}/refresh").status_code == 409


@pytest.mark.no_worker
def test_a_refresh_runs_its_sources_and_those_never_run(client: TestClient) -> None:
    inventory_id, one, two, groups = _setup(client)
    claimed = ClaimedRefresh()  # the first: both new sources
    job = claimed.job().json()
    assert sorted(c["key"] for c in job["calls"]) == sorted([f"s{one['id']}", f"s{two['id']}"])
    _finish_all()
    db = get_sessionmaker()()
    db.execute(
        update(InventorySource).where(InventorySource.id == two["id"]).values(last_queued_at=None)
    )
    db.commit()
    db.close()
    client.post(f"/api/inventories/{inventory_id}/sources/{one['id']}/refresh")
    claimed = ClaimedRefresh()
    job = claimed.job().json()
    # one: what it is for; two: changed since it last ran (as an edit leaves it).
    assert sorted(c["key"] for c in job["calls"]) == sorted([f"s{one['id']}", f"s{two['id']}"])
    _finish_all()
    client.post(f"/api/inventories/{inventory_id}/sources/{one['id']}/refresh")
    claimed = ClaimedRefresh()
    assert [c["key"] for c in claimed.job().json()["calls"]] == [f"s{one['id']}"]
    rows = {r["name"]: r["ran"] for r in client.get(
        f"/api/inventories/{inventory_id}/refreshes?limit=1"
    ).json()[0]["source_results"]}  # fmt: skip
    assert rows == {"one": True, "two": False, "groups": False}
    assert groups["id"]


@pytest.mark.no_worker
@pytest.mark.parametrize(
    ("value", "ok"), [(None, True), (0, True), (300, True), (60, False), (10**7, False)]
)
def test_a_sources_interval_is_checked(client: TestClient, value, ok) -> None:
    _login(client)
    inventory_id = client.post("/api/inventories", json={"name": "dyn"}).json()["id"]
    response = client.post(
        f"/api/inventories/{inventory_id}/sources",
        json={"name": "one", "config": _gen("one"), "refresh_interval_seconds": value},
    )
    assert (response.status_code == 201) == ok, response.text


@pytest.mark.no_worker
def test_a_source_says_how_often_and_when_it_runs_next(client: TestClient) -> None:
    inventory_id, _one, two, _groups = _setup(client)
    client.put(
        f"/api/inventories/{inventory_id}/refresh-settings", json={"refresh_interval_seconds": 3600}
    )
    sources = {s["name"]: s for s in client.get(f"/api/inventories/{inventory_id}/sources").json()}
    assert sources["one"]["refresh_interval_seconds"] is None
    assert sources["one"]["effective_interval_seconds"] == 3600
    assert sources["one"]["next_refresh_at"] is not None  # an hour after it was last queued
    assert (
        sources["two"]["effective_interval_seconds"] == 0
        and sources["two"]["next_refresh_at"] is None
    )
    assert sources["groups"]["effective_interval_seconds"] == 0
    client.patch(
        f"/api/inventories/{inventory_id}/sources/{two['id']}",
        json={"refresh_interval_seconds": None},
    )
    two_now = client.get(f"/api/inventories/{inventory_id}/sources").json()
    assert {s["name"]: s["effective_interval_seconds"] for s in two_now}["two"] == 3600


def test_an_edit_of_the_inventorys_hosts_only_combines(client: TestClient) -> None:
    """A real worker: the inventory's own new host is in the snapshot, no source ran."""
    _login(client)
    inventory_id = _inventory(client)
    _add_source(client, inventory_id, "one", _gen("one"))
    assert _wait_refresh(client, inventory_id)["status"] == "success"
    client.post(f"/api/inventories/{inventory_id}/hosts", json={"hostname": "new1", "vars": {}})
    refresh = _wait_refresh(client, inventory_id)
    assert refresh["status"] == "success" and refresh["trigger"] == "static_changed"
    assert [r["ran"] for r in refresh["source_results"]] == [False]
    hosts = client.get(f"/api/inventories/{inventory_id}/hosts").json()["hosts"]
    assert {"new1", "one-a", "one-b"} <= {h["name"] for h in hosts}


def test_the_alert_stays_while_another_source_still_fails(client: TestClient) -> None:
    _login(client)
    inventory_id = _inventory(client)
    good = _add_source(client, inventory_id, "good", _gen("good"))
    broken = (
        "plugin: netbox.netbox.nb_inventory\napi_endpoint: http://127.0.0.1:1\n"
        "token: \"{{ lookup('env', 'T') }}\"\n"
    )
    _add_source(client, inventory_id, "bad", broken)
    assert _wait_refresh(client, inventory_id)["status"] == "failed"

    def alerts() -> list[str]:
        db = get_sessionmaker()()
        try:
            return list(
                db.scalars(
                    select(NotificationAlert.key).where(NotificationAlert.key.like("inventory.%"))
                )
            )
        finally:
            db.close()

    assert alerts() == [f"inventory.refresh_failed:{inventory_id}"]
    client.post(f"/api/inventories/{inventory_id}/sources/{good['id']}/refresh")
    assert _wait_refresh(client, inventory_id)["status"] == "success"  # only "good" ran
    assert alerts() == [f"inventory.refresh_failed:{inventory_id}"]  # "bad" still fails
    client.patch(f"/api/inventories/{inventory_id}/sources/{good['id']}", json={"position": 2})
    db = get_sessionmaker()()
    db.execute(update(InventorySource).where(InventorySource.name == "bad").values(enabled=False))
    db.commit()
    db.close()
    client.post(f"/api/inventories/{inventory_id}/sources/{good['id']}/refresh")
    assert _wait_refresh(client, inventory_id)["status"] == "success"
    assert alerts() == []  # the only failing source is off now
