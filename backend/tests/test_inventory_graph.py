"""The group graph (Phase 5C-2): how an inventory's groups nest, with direct host counts, and
the host list narrowed to a group and the groups below it. Names and counts only: never vars."""

import pytest
from fastapi.testclient import TestClient

from app.db import get_sessionmaker
from app.main import app
from app.models import Inventory, InventorySnapshot, InventorySource
from tests.conftest import make_user_client
from tests.test_projects import _member, _project
from tests.test_runs import _login

pytestmark = pytest.mark.no_worker  # snapshots are planted directly; nothing is refreshed

SECRET = "s3cr3t-value-that-must-never-show"


def _static(client: TestClient, name: str = "lab") -> int:
    """web1 and web2 in "web", db1 in "db", lonely in no group; host vars hold a secret."""
    inventory_id = client.post("/api/inventories", json={"name": name}).json()["id"]
    web = client.post(f"/api/inventories/{inventory_id}/groups", json={"name": "web"}).json()
    db = client.post(f"/api/inventories/{inventory_id}/groups", json={"name": "db"}).json()
    for hostname, groups in (("web1", [web]), ("web2", [web]), ("db1", [db]), ("lonely", [])):
        response = client.post(
            f"/api/inventories/{inventory_id}/hosts",
            json={
                "hostname": hostname,
                "vars": {"ansible_password": SECRET, "note": SECRET},
                "group_ids": [g["id"] for g in groups],
            },
        )
        assert response.status_code == 201, response.text
    return inventory_id


def _plant(inventory_id: int, data: dict) -> int:
    """A source and its current snapshot, as a refresh would leave them."""
    db = get_sessionmaker()()
    source = InventorySource(
        inventory_id=inventory_id,
        name="cloud",
        plugin="ansible.builtin.constructed",
        config="plugin: ansible.builtin.constructed\n",
        created_by="admin",
    )
    snapshot = InventorySnapshot(
        inventory_id=inventory_id,
        data=data,
        sha256="0" * 64,
        host_count=len(data["hosts"]),
        group_count=len(data["groups"]),
    )
    db.add_all([source, snapshot])
    db.flush()
    db.get(Inventory, inventory_id).current_snapshot_id = snapshot.id
    db.commit()
    snapshot_id = snapshot.id
    db.close()
    return snapshot_id


def _group(name: str, hosts=(), children=(), group_vars=None) -> tuple[str, dict]:
    return name, {"hosts": list(hosts), "children": list(children), "vars": group_vars or {}}


# Nesting from a source: prod and eu both contain "web" (two parents); "web" contains web_eu;
# "db" is the inventory's own group and a source's too.
NESTED = {
    "vars": {"api_token": SECRET},
    "hosts": {
        "web1": {},
        "db1": {},
        "gen-eu-1": {"vault_password": SECRET},
        "gen-eu-2": {},
        "orphan": {},
    },
    "groups": dict(
        [
            _group("prod", children=["web", "db"]),
            _group("eu", children=["web"], group_vars={"region_secret": SECRET}),
            _group("web", hosts=["web1"], children=["web_eu"]),
            _group("web_eu", hosts=["gen-eu-1", "gen-eu-2"]),
            _group("db", hosts=["gen-eu-2"]),
        ]
    ),
    "static_hosts": ["web1", "web2", "db1", "lonely"],
}


def test_a_static_inventory_is_a_flat_list_of_groups(client: TestClient) -> None:
    _login(client)
    inventory_id = _static(client)
    graph = client.get(f"/api/inventories/{inventory_id}/graph").json()
    assert graph == {
        "name": "lab",
        "hosts": 4,
        "ungrouped": 1,
        "groups": [
            {"name": "db", "hosts": 1, "children": [], "origin": "static"},
            {"name": "web", "hosts": 2, "children": [], "origin": "static"},
        ],
        "snapshot_id": None,
        "snapshot_at": None,
    }


def test_groups_from_sources_nest_and_say_where_they_come_from(client: TestClient) -> None:
    _login(client)
    inventory_id = _static(client)
    snapshot_id = _plant(inventory_id, NESTED)
    graph = client.get(f"/api/inventories/{inventory_id}/graph").json()
    assert graph["snapshot_id"] == snapshot_id and graph["snapshot_at"]
    groups = {g["name"]: g for g in graph["groups"]}
    assert [g["name"] for g in graph["groups"]] == sorted(groups)
    assert groups["prod"] == {
        "name": "prod",
        "hosts": 0,
        "children": ["web", "db"],
        "origin": "source",
    }
    assert groups["eu"]["children"] == ["web"]  # web has two parents: prod and eu
    assert groups["web"] == {"name": "web", "hosts": 2, "children": ["web_eu"], "origin": "both"}
    # db: the source's gen-eu-2 plus the inventory's own db1
    assert groups["db"] == {"name": "db", "hosts": 2, "children": [], "origin": "both"}
    assert groups["web_eu"]["origin"] == "source"
    # web1, web2, db1, lonely + gen-eu-1, gen-eu-2, orphan; lonely and orphan are in no group
    assert graph["hosts"] == 7 and graph["ungrouped"] == 2


def test_a_snapshot_left_after_its_sources_are_gone_is_ignored(client: TestClient) -> None:
    _login(client)
    inventory_id = _static(client)
    _plant(inventory_id, NESTED)
    db = get_sessionmaker()()
    db.query(InventorySource).filter(InventorySource.inventory_id == inventory_id).delete()
    db.commit()
    db.close()
    graph = client.get(f"/api/inventories/{inventory_id}/graph").json()
    assert {g["name"] for g in graph["groups"]} == {"web", "db"}
    assert graph["snapshot_id"] is None and graph["hosts"] == 4


def test_the_graph_never_carries_vars(client: TestClient) -> None:
    _login(client)
    inventory_id = _static(client)
    _plant(inventory_id, NESTED)
    response = client.get(f"/api/inventories/{inventory_id}/graph")
    assert response.status_code == 200
    assert SECRET not in response.text
    body = response.json()
    assert set(body) == {"name", "hosts", "ungrouped", "groups", "snapshot_id", "snapshot_at"}
    assert all(set(g) == {"name", "hosts", "children", "origin"} for g in body["groups"])


def test_hosts_narrow_to_a_group_and_the_groups_below_it(client: TestClient) -> None:
    _login(client)
    inventory_id = _static(client)
    _plant(inventory_id, NESTED)
    base = f"/api/inventories/{inventory_id}/hosts"

    def names(query: str) -> tuple[int, list[str]]:
        body = client.get(f"{base}?{query}").json()
        return body["total"], [h["name"] for h in body["hosts"]]

    # prod -> web (web1, web2) -> web_eu (gen-eu-1, gen-eu-2); prod -> db (db1, gen-eu-2)
    assert names("group=prod") == (5, ["db1", "gen-eu-1", "gen-eu-2", "web1", "web2"])
    assert names("group=web_eu") == (2, ["gen-eu-1", "gen-eu-2"])
    assert names("group=prod&q=eu") == (2, ["gen-eu-1", "gen-eu-2"])
    # vars are still masked when narrowed
    hosts = client.get(f"{base}?group=web_eu").json()["hosts"]
    assert SECRET not in str(hosts)
    response = client.get(f"{base}?group=nope")
    assert response.status_code == 404
    assert response.json()["detail"] == "Group not found"


def test_hosts_in_a_big_group_are_paged(client: TestClient) -> None:
    _login(client)
    inventory_id = client.post("/api/inventories", json={"name": "big"}).json()["id"]
    hosts = {f"h{n:03}": {} for n in range(150)}
    _plant(
        inventory_id,
        {
            "vars": {},
            "hosts": hosts,
            "groups": dict(
                [_group("all_of_them", children=["half"]), _group("half", hosts=list(hosts)[:120])]
            ),
            "static_hosts": [],
        },
    )
    first = client.get(f"/api/inventories/{inventory_id}/hosts?group=all_of_them").json()
    second = client.get(f"/api/inventories/{inventory_id}/hosts?group=all_of_them&page=2").json()
    assert first["total"] == second["total"] == 120
    assert len(first["hosts"]) == 100 and len(second["hosts"]) == 20
    assert second["hosts"][-1]["name"] == "h119"


def test_the_graph_handles_an_inventory_at_its_limits(client: TestClient) -> None:
    """5,000 groups over several levels, some with several parents, and 20,000 hosts."""
    _login(client)
    inventory_id = client.post("/api/inventories", json={"name": "huge"}).json()["id"]
    hosts = {f"host-{n:05}": {} for n in range(20_000)}
    names = list(hosts)
    groups: dict[str, dict] = {}
    for n in range(5_000):
        children = [f"g{c}" for c in (2 * n + 1, 2 * n + 2, 3 * n + 3) if c < 5_000]
        groups[f"g{n}"] = {"hosts": names[4 * n : 4 * n + 4], "children": children, "vars": {}}
    _plant(inventory_id, {"vars": {}, "hosts": hosts, "groups": groups, "static_hosts": []})
    response = client.get(f"/api/inventories/{inventory_id}/graph")
    assert response.status_code == 200
    graph = response.json()
    assert len(graph["groups"]) == 5_000 and graph["hosts"] == 20_000 and graph["ungrouped"] == 0
    assert client.get(f"/api/inventories/{inventory_id}/hosts?group=g0").json()["total"] == 20_000


def test_who_may_see_the_graph(client: TestClient) -> None:
    _login(client)
    inventory_id = _static(client)
    path = f"/api/inventories/{inventory_id}/graph"
    assert TestClient(app).get(path).status_code == 401
    assert make_user_client("viewer1", "viewer").get(path).status_code == 200
    key = client.post(
        "/api/projects/1/api-keys",
        json={"name": "ro", "preset": "read-only", "current_password": "admin"},
    )
    assert key.status_code == 201, key.text
    # Like /targets and /hosts, the graph is for the UI: API keys can't use it.
    reader = TestClient(app, headers={"Authorization": f"Bearer {key.json()['token']}"})
    assert reader.get(path).status_code == 403
    other = _member(client, "outsider", {_project(client, "Elsewhere"): "admin"})
    assert other.get(path).status_code == 404
    assert other.get(f"/api/inventories/{inventory_id}/hosts?group=web").status_code == 404
