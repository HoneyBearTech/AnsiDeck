import asyncio

import pytest
from fastapi.testclient import TestClient
from psycopg.errors import InvalidTextRepresentation
from sqlalchemy.exc import DataError
from starlette.requests import Request

from app.main import _integer_out_of_range
from tests.test_projects import _admin

# Beyond Postgres' INTEGER (and any 64-bit) range: it cannot match any row.
TOO_BIG = 99999999999999999999999999


@pytest.fixture
def admin(client: TestClient) -> TestClient:
    return _admin(client)


def test_a_huge_id_in_the_path_is_not_found(admin: TestClient) -> None:
    for path in ("playbooks", "inventories", "runs"):
        response = admin.get(f"/api/{path}/{TOO_BIG}")
        assert response.status_code == 404, path
        assert response.json() == {"detail": "Not found"}
    assert (
        admin.put(f"/api/playbooks/{TOO_BIG}", json={"content": "- hosts: all\n"}).status_code
        == 404
    )
    assert admin.delete(f"/api/playbooks/{TOO_BIG}").status_code == 404
    assert admin.patch(f"/api/users/{TOO_BIG}", json={"is_active": True}).status_code == 404


def test_a_huge_id_in_a_query_or_body_is_not_found(admin: TestClient) -> None:
    assert admin.get("/api/playbooks", params={"project_id": TOO_BIG}).status_code == 404
    assert admin.get("/api/runs", params={"project_id": TOO_BIG}).status_code == 404
    created = admin.post(
        "/api/playbooks", json={"name": "x", "content": "- hosts: all\n", "project_id": TOO_BIG}
    )
    assert created.status_code == 404
    run = admin.post(
        "/api/runs",
        json={"playbook_id": TOO_BIG, "inventory_id": TOO_BIG, "credential_id": TOO_BIG},
    )
    assert run.status_code == 404


def test_the_largest_valid_id_is_still_an_ordinary_lookup(admin: TestClient) -> None:
    assert admin.get(f"/api/playbooks/{2**31 - 1}").status_code == 404  # no such row
    assert admin.get(f"/api/playbooks/{2**31}").status_code == 404  # beyond INTEGER
    assert admin.get(f"/api/playbooks/{-(2**31) - 1}").status_code == 404
    assert admin.get("/api/playbooks/0").status_code == 404
    assert admin.get("/api/playbooks").status_code == 200


def test_an_unrelated_data_error_is_not_swallowed() -> None:
    request = Request({"type": "http", "method": "GET", "path": "/", "headers": []})
    other = DataError("SELECT 1", {}, InvalidTextRepresentation("something else"))
    with pytest.raises(DataError, match="something else"):
        asyncio.run(_integer_out_of_range(request, other))
