from fastapi.testclient import TestClient


def _login(client: TestClient) -> None:
    response = client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    assert response.status_code == 200


def _create_inventory(client: TestClient, name: str = "homelab") -> int:
    response = client.post("/api/inventories", json={"name": name, "description": "test"})
    assert response.status_code == 201
    return response.json()["id"]


def test_inventory_crud_requires_auth(client: TestClient) -> None:
    assert client.get("/api/inventories").status_code == 401
    assert client.post("/api/inventories", json={"name": "x"}).status_code == 401
    assert client.get("/api/inventories/1").status_code == 401
    assert client.post("/api/inventories/1/groups", json={"name": "x"}).status_code == 401
    assert client.post("/api/inventories/1/hosts", json={"hostname": "x"}).status_code == 401


def test_create_inventory_and_fetch_detail(client: TestClient) -> None:
    _login(client)
    inventory_id = _create_inventory(client)

    detail = client.get(f"/api/inventories/{inventory_id}")
    assert detail.status_code == 200
    body = detail.json()
    assert body["name"] == "homelab"
    assert body["groups"] == []
    assert body["hosts"] == []


def test_group_and_host_crud_within_inventory(client: TestClient) -> None:
    _login(client)
    inventory_id = _create_inventory(client)

    group_response = client.post(f"/api/inventories/{inventory_id}/groups", json={"name": "web"})
    assert group_response.status_code == 201
    group_id = group_response.json()["id"]

    host_response = client.post(
        f"/api/inventories/{inventory_id}/hosts",
        json={
            "hostname": "host1.local",
            "vars": {"ansible_user": "deploy"},
            "group_ids": [group_id],
        },
    )
    assert host_response.status_code == 201
    host_id = host_response.json()["id"]
    assert host_response.json()["group_ids"] == [group_id]

    detail = client.get(f"/api/inventories/{inventory_id}").json()
    assert detail["hosts"][0]["group_ids"] == [group_id]

    unassign_response = client.put(
        f"/api/inventories/{inventory_id}/hosts/{host_id}", json={"group_ids": []}
    )
    assert unassign_response.status_code == 200
    assert unassign_response.json()["group_ids"] == []


def test_host_can_belong_to_multiple_groups(client: TestClient) -> None:
    _login(client)
    inventory_id = _create_inventory(client)

    group_a = client.post(f"/api/inventories/{inventory_id}/groups", json={"name": "a"}).json()[
        "id"
    ]
    group_b = client.post(f"/api/inventories/{inventory_id}/groups", json={"name": "b"}).json()[
        "id"
    ]

    host_response = client.post(
        f"/api/inventories/{inventory_id}/hosts",
        json={"hostname": "multi.local", "group_ids": [group_a, group_b]},
    )
    assert host_response.status_code == 201
    assert set(host_response.json()["group_ids"]) == {group_a, group_b}


def test_deleting_group_removes_membership_but_not_host(client: TestClient) -> None:
    _login(client)
    inventory_id = _create_inventory(client)
    group_id = client.post(f"/api/inventories/{inventory_id}/groups", json={"name": "web"}).json()[
        "id"
    ]
    host_id = client.post(
        f"/api/inventories/{inventory_id}/hosts",
        json={"hostname": "host1.local", "group_ids": [group_id]},
    ).json()["id"]

    delete_response = client.delete(f"/api/inventories/{inventory_id}/groups/{group_id}")
    assert delete_response.status_code == 204

    detail = client.get(f"/api/inventories/{inventory_id}").json()
    assert detail["groups"] == []
    assert len(detail["hosts"]) == 1
    assert detail["hosts"][0]["id"] == host_id
    assert detail["hosts"][0]["group_ids"] == []


def test_deleting_inventory_cascades_groups_and_hosts(client: TestClient) -> None:
    _login(client)
    inventory_id = _create_inventory(client)
    client.post(f"/api/inventories/{inventory_id}/groups", json={"name": "web"})
    client.post(f"/api/inventories/{inventory_id}/hosts", json={"hostname": "host1.local"})

    delete_response = client.delete(f"/api/inventories/{inventory_id}")
    assert delete_response.status_code == 204

    assert client.get(f"/api/inventories/{inventory_id}").status_code == 404


def test_host_group_id_must_belong_to_same_inventory(client: TestClient) -> None:
    _login(client)
    inventory_a = _create_inventory(client, name="a")
    inventory_b = _create_inventory(client, name="b")
    group_in_b = client.post(f"/api/inventories/{inventory_b}/groups", json={"name": "web"}).json()[
        "id"
    ]

    response = client.post(
        f"/api/inventories/{inventory_a}/hosts",
        json={"hostname": "host1.local", "group_ids": [group_in_b]},
    )
    assert response.status_code == 400
