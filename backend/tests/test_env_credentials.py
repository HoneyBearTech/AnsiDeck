"""Environment-variable credentials (Phase 4G-1): named values for inventory plugins, stored
encrypted or read whole from the secret store, never shown, never usable as an SSH key."""

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text

from app.db import Base, get_engine, get_sessionmaker
from app.env_credentials import check_env, name_problem, resolve_env
from app.models import AuditEvent, Credential
from app.secret_store import SecretStoreError
from app.subprocess_env import PASSTHROUGH_ENV
from app.worker.__main__ import FORBIDDEN_ENV
from tests.test_runs import _create_inventory_with_host, _create_playbook, _login
from tests.test_secret_store import store  # noqa: F401 - the mocked secret store fixture

SENTINEL = "nb-token-sentinel-6f1c2a"


def _rows_containing(value: str) -> list[str]:
    hits = []
    with get_engine().connect() as conn:
        for table in Base.metadata.sorted_tables:
            rows = conn.execute(text(f'SELECT row_to_json(t)::text FROM "{table.name}" t'))
            hits += [table.name for (row,) in rows if value in row]
    return hits


def test_an_env_credential_is_stored_encrypted_and_shows_only_names(client: TestClient) -> None:
    _login(client)
    response = client.post(
        "/api/credentials",
        json={"name": "netbox", "kind": "env", "env": {"NETBOX_TOKEN": SENTINEL, "NB_X": "y"}},
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["kind"] == "env" and body["env_names"] == ["NB_X", "NETBOX_TOKEN"]
    assert SENTINEL not in response.text
    assert _rows_containing(SENTINEL) == []  # encrypted at rest, not in the audit log

    listed = client.get("/api/credentials?kind=env").json()
    assert [c["name"] for c in listed] == ["netbox"]
    assert client.get("/api/credentials?kind=ssh").json() == []
    check = client.post(f"/api/credentials/{body['id']}/check").json()
    assert check == {
        "ok": True,
        "version": None,
        "env_names": ["NB_X", "NETBOX_TOKEN"],
        "error_kind": None,
        "error": None,
    }

    db = get_sessionmaker()()
    credential = db.get(Credential, body["id"])
    assert resolve_env(credential) == {"NETBOX_TOKEN": SENTINEL, "NB_X": "y"}
    audit = db.scalars(select(AuditEvent).where(AuditEvent.action == "credential.create")).one()
    assert audit.detail == {"kind": "env", "names": ["NB_X", "NETBOX_TOKEN"]}
    db.close()


@pytest.mark.parametrize(
    ("env", "message"),
    [
        ({"netbox_token": "x"}, "not a valid name"),
        ({"PATH": "/tmp"}, "can't be set"),
        ({"LD_PRELOAD": "/tmp/x.so"}, "can't be set"),
        ({"ANSIBLE_CONFIG": "/tmp/a.cfg"}, "can't be set"),
        ({"PYTHONPATH": "/tmp"}, "can't be set"),
        ({"AWS_EC2_METADATA_DISABLED": "false"}, "can't be set"),
        ({"T": ""}, "non-empty"),
        ({"T": "a\x00b"}, "NUL"),
        ({"T\n": "x"}, "not a valid name"),
        ({f"V{i}": "x" for i in range(33)}, "at most 32"),
        ({}, "at least one"),
    ],
)
def test_bad_variables_are_refused(client: TestClient, env: dict, message: str) -> None:
    _login(client)
    response = client.post("/api/credentials", json={"name": "bad", "kind": "env", "env": env})
    assert response.status_code == 400 and message in response.json()["detail"], response.text


def test_kinds_do_not_mix(client: TestClient) -> None:
    _login(client)
    for body in (
        {"kind": "env", "private_key": "k"},
        {"kind": "ssh", "env": {"T": "x"}},
        {"kind": "env", "store_path": "p", "store_key": "k"},
        {"kind": "env"},
    ):
        response = client.post("/api/credentials", json={"name": "mixed", **body})
        assert response.status_code == 422, body


def test_an_env_credential_cannot_run_a_playbook_or_be_a_deploy_key(
    client: TestClient, tmp_path
) -> None:
    _login(client)
    env_id = client.post(
        "/api/credentials", json={"name": "envy", "kind": "env", "env": {"T": "x"}}
    ).json()["id"]
    inventory_id, _ = _create_inventory_with_host(client, str(tmp_path / "m"))
    run = client.post(
        "/api/runs",
        json={
            "playbook_id": _create_playbook(client, "- hosts: all\n  tasks: []\n"),
            "inventory_id": inventory_id,
            "credential_id": env_id,
        },
    )
    assert run.status_code == 400 and run.json()["detail"] == "A run needs an SSH key credential"
    source = client.post(
        "/api/projects/1/git-sources",
        json={
            "name": "repo",
            "url": "git@example.com:org/repo.git",
            "auth_kind": "ssh_key",
            "credential_id": env_id,
        },
    )
    assert source.status_code == 400 and "SSH key" in source.json()["detail"]


def test_an_env_credential_can_be_a_whole_secret_in_the_store(
    client: TestClient,
    store,  # noqa: F811
    monkeypatch,
) -> None:
    _login(client)
    path = "/v1/secret/data/ansideck/1/web/netbox"
    store["secrets"][path] = {"NETBOX_TOKEN": SENTINEL}
    response = client.post(
        "/api/credentials", json={"name": "nb", "kind": "env", "store_path": "web/netbox"}
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["store_location"] == "secret/ansideck/1/web/netbox"
    assert body["env_names"] is None and SENTINEL not in json.dumps(body)

    store["secrets"][path] = {"NETBOX_TOKEN": SENTINEL, "EXTRA": "z"}  # rotated in the store
    check = client.post(f"/api/credentials/{body['id']}/check").json()
    assert check["ok"] and check["env_names"] == ["EXTRA", "NETBOX_TOKEN"]
    db = get_sessionmaker()()
    assert resolve_env(db.get(Credential, body["id"]))["NETBOX_TOKEN"] == SENTINEL

    store["secrets"][path] = {"lower_case": "x"}
    with pytest.raises(SecretStoreError) as error:
        resolve_env(db.get(Credential, body["id"]))
    assert error.value.kind == "bad_value" and "x" not in str(error.value).split(":")[-1]
    db.close()
    bad = client.post(
        "/api/credentials", json={"name": "nb2", "kind": "env", "store_path": "web/netbox"}
    )
    assert bad.status_code == 400 and "keys can't be used" in bad.json()["detail"]
    assert _rows_containing(SENTINEL) == []


def test_the_deny_list_covers_the_workers_own_environment() -> None:
    for name in (*FORBIDDEN_ENV, *(n for n in PASSTHROUGH_ENV if n.isupper())):
        assert name_problem(name) is not None, name
    assert check_env({"NETBOX_TOKEN": "t", "AWS_ACCESS_KEY_ID": "a"})
