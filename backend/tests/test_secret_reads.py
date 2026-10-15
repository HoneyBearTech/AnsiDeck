"""What a run's job read from the secret store (runs.secret_reads: each reference's location
and KV version, the location shown only to those who may list the project's secrets), and
pointing a credential's or vault password's reference elsewhere (PATCH): checked by reading
it, refused for secrets stored here, locked against a concurrent edit, audited, and picked up
by queued runs."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db import get_sessionmaker
from app.models import AuditEvent, Credential
from app.routers import credentials as credentials_router
from tests.conftest import internal_client, make_user_client
from tests.test_credentials import _generate_key_pem
from tests.test_runs import (
    SUCCESS_PLAYBOOK,
    _create_inventory_with_host,
    _create_playbook,
    _login,
)
from tests.test_secret_store import store  # noqa: F401 - the mocked secret store fixture

DATA = "/v1/secret/data/ansideck/1/"
KEY = _generate_key_pem()


def _post(client: TestClient, url: str, body: dict) -> int:
    response = client.post(url, json=body)
    assert response.status_code == 201, response.text
    return response.json()["id"]


def _references(client: TestClient, store) -> dict:  # noqa: F811
    store["secrets"][DATA + "web/ssh"] = {"private_key": KEY}
    store["secrets"][DATA + "web/ssh2"] = {"private_key": KEY, "empty": ""}
    store["secrets"][DATA + "ansible/vault"] = {"password": "vault-pw-sentinel", "empty": " "}
    store["secrets"][DATA + "cloud/aws"] = {"AWS_ACCESS_KEY_ID": "AKIAEXAMPLE12345"}
    store["secrets"][DATA + "cloud/gcp"] = {"GOOGLE_PROJECT": "demo"}
    store["versions"].update({DATA + "web/ssh": 4, DATA + "ansible/vault": 9})
    return {
        "ssh": _post(client, "/api/credentials", {"name": "ssh", "store_path": "web/ssh"}),
        "vault": _post(
            client, "/api/vault-passwords", {"name": "vault", "store_path": "ansible/vault"}
        ),
        "env": _post(
            client, "/api/credentials", {"name": "aws", "kind": "env", "store_path": "cloud/aws"}
        ),
    }


def _queue_run(client: TestClient, tmp_path, refs: dict) -> int:
    inventory_id, _ = _create_inventory_with_host(client, str(tmp_path / "m"))
    return _post(
        client,
        "/api/runs",
        {
            "playbook_id": _create_playbook(client, SUCCESS_PLAYBOOK),
            "inventory_id": inventory_id,
            "credential_id": refs["ssh"],
            "vault_password_id": refs["vault"],
            "env_credential_ids": [refs["env"]],
        },
    )


def _start(run_id: int):
    http = internal_client()
    claim = http.post(
        "/internal/claim", json={"worker_id": "w", "wait_seconds": 0, "host_keys": True}
    ).json()
    assert claim["run_id"] == run_id
    return http.post(
        f"/internal/runs/{run_id}/job",
        json={"job_token": claim["job_token"]},
        headers={"X-Claim-Token": claim["claim_token"]},
    )


@pytest.mark.no_worker
def test_a_run_records_the_versions_it_read(client: TestClient, store, tmp_path) -> None:  # noqa: F811
    _login(client)
    run_id = _queue_run(client, tmp_path, _references(client, store))
    assert client.get(f"/api/runs/{run_id}").json()["secret_reads"] is None  # not started yet

    job = _start(run_id)
    assert job.status_code == 200, job.text
    reads = client.get(f"/api/runs/{run_id}").json()["secret_reads"]
    assert reads == [
        {
            "what": "credential",
            "name": "ssh",
            "location": "secret/ansideck/1/web/ssh#private_key",
            "version": 4,
        },
        {
            "what": "vault_password",
            "name": "vault",
            "location": "secret/ansideck/1/ansible/vault#password",
            "version": 9,
        },
        {
            "what": "env_credential",
            "name": "aws",
            "location": "secret/ansideck/1/cloud/aws",
            "version": 3,
        },
    ]

    operator = make_user_client("o1", "operator")  # may list secrets
    assert operator.get(f"/api/runs/{run_id}").json()["secret_reads"] == reads
    viewer = make_user_client("v1", "viewer")
    for path in (f"/api/runs/{run_id}", "/api/runs"):
        body = viewer.get(path).json()
        seen = (body if isinstance(body, dict) else body[0])["secret_reads"]
        assert [r["location"] for r in seen] == [None] * 3
        assert [r["version"] for r in seen] == [4, 9, 3]
        assert "ansible/vault" not in str(body)


@pytest.mark.no_worker
def test_a_run_whose_secrets_are_stored_here_records_no_reads(
    client: TestClient,
    store,  # noqa: F811
    tmp_path,
) -> None:
    _login(client)
    inventory_id, _ = _create_inventory_with_host(client, str(tmp_path / "m"))
    run_id = _post(
        client,
        "/api/runs",
        {
            "playbook_id": _create_playbook(client, SUCCESS_PLAYBOOK),
            "inventory_id": inventory_id,
            "credential_id": _post(
                client, "/api/credentials", {"name": "here", "private_key": KEY}
            ),
        },
    )
    assert _start(run_id).status_code == 200
    assert client.get(f"/api/runs/{run_id}").json()["secret_reads"] is None


@pytest.mark.no_worker
def test_a_failed_read_leaves_no_partial_record(client: TestClient, store, tmp_path) -> None:  # noqa: F811
    _login(client)
    run_id = _queue_run(client, tmp_path, _references(client, store))
    store["status"][DATA + "cloud/aws"] = (404, {"errors": []})  # gone (an outage would wait)
    assert _start(run_id).status_code == 410
    run = client.get(f"/api/runs/{run_id}").json()
    assert run["status"] == "failed" and run["secret_reads"] is None


def _audit(action: str) -> list[dict]:
    db = get_sessionmaker()()
    try:
        return [
            e.detail
            for e in db.scalars(
                select(AuditEvent).where(AuditEvent.action == action).order_by(AuditEvent.id)
            )
        ]
    finally:
        db.close()


@pytest.mark.no_worker
def test_a_reference_can_be_pointed_elsewhere(client: TestClient, store, tmp_path) -> None:  # noqa: F811
    _login(client)
    refs = _references(client, store)
    run_id = _queue_run(client, tmp_path, refs)  # queued: it reads the new references

    moved = client.patch(f"/api/credentials/{refs['ssh']}", json={"store_path": "web/ssh2"})
    assert moved.status_code == 200, moved.text
    assert moved.json()["store_location"] == "secret/ansideck/1/web/ssh2#private_key"
    vault = client.patch(f"/api/vault-passwords/{refs['vault']}", json={"store_key": "password"})
    assert vault.status_code == 200 and vault.json()["store_path"] == "ansible/vault"
    env = client.patch(f"/api/credentials/{refs['env']}", json={"store_path": "cloud/gcp"})
    assert env.status_code == 200 and env.json()["store_location"] == "secret/ansideck/1/cloud/gcp"

    assert _audit("credential.reference_update") == [
        {
            "location_before": "secret/ansideck/1/web/ssh#private_key",
            "location": "secret/ansideck/1/web/ssh2#private_key",
            "version": 3,
        },
        {
            "location_before": "secret/ansideck/1/cloud/aws",
            "location": "secret/ansideck/1/cloud/gcp",
            "names": ["GOOGLE_PROJECT"],
            "version": 3,
        },
    ]
    assert _audit("vault_password.reference_update")[0]["version"] == 9

    assert _start(run_id).status_code == 200
    reads = client.get(f"/api/runs/{run_id}").json()["secret_reads"]
    assert [r["location"] for r in reads] == [
        "secret/ansideck/1/web/ssh2#private_key",
        "secret/ansideck/1/ansible/vault#password",
        "secret/ansideck/1/cloud/gcp",
    ]


@pytest.mark.no_worker
def test_a_new_reference_is_checked_before_it_is_kept(client: TestClient, store) -> None:  # noqa: F811
    _login(client)
    refs = _references(client, store)
    ssh, vault, env = (
        f"/api/credentials/{refs['ssh']}",
        f"/api/vault-passwords/{refs['vault']}",
        f"/api/credentials/{refs['env']}",
    )
    for url, body, message in [
        (ssh, {"store_path": "web/nope"}, "no secret at that path"),
        (ssh, {"store_key": "nope"}, "no such key"),
        (ssh, {"store_key": "empty"}, ""),
        (ssh, {"store_path": "../2/web"}, ""),
        (vault, {"store_key": "empty"}, "empty"),
        (env, {"store_key": "x"}, "no store_key"),
    ]:
        refused = client.patch(url, json=body)
        assert refused.status_code == 400 and message in refused.text, (body, refused.text)
    assert client.patch(ssh, json={}).status_code == 422
    assert client.get("/api/credentials").json()[1]["store_path"] == "web/ssh"
    assert _audit("credential.reference_update") == []


@pytest.mark.no_worker
def test_only_references_can_be_edited_and_only_by_secret_managers(
    client: TestClient,
    store,  # noqa: F811
) -> None:
    _login(client)
    refs = _references(client, store)
    here = _post(client, "/api/credentials", {"name": "here", "private_key": KEY})
    refused = client.patch(f"/api/credentials/{here}", json={"store_path": "web/ssh2"})
    assert refused.status_code == 409 and "stored in AnsiDeck" in refused.text
    db = get_sessionmaker()()
    cert = Credential(
        name="cert",
        kind="ssh_cert",
        ssh_mount="ssh",
        ssh_role="ops",
        ssh_principals=["deploy"],
        project_id=1,
    )
    db.add(cert)
    db.commit()
    cert_id = cert.id
    db.close()
    refused = client.patch(f"/api/credentials/{cert_id}", json={"store_path": "web/ssh2"})
    assert refused.status_code == 400 and "no reference" in refused.text

    operator = make_user_client("o1", "operator")
    url = f"/api/credentials/{refs['ssh']}"
    assert operator.patch(url, json={"store_path": "web/ssh2"}).status_code == 403
    assert client.patch("/api/credentials/99999", json={"store_path": "x"}).status_code == 404


@pytest.mark.no_worker
def test_a_reference_changed_while_checking_is_not_overwritten(
    client: TestClient,
    store,  # noqa: F811
    monkeypatch,
) -> None:
    _login(client)
    refs = _references(client, store)
    real = credentials_router.read_reference

    def racing(project_id: int, path: str, key: str):
        db = get_sessionmaker()()
        db.get(Credential, refs["ssh"]).store_key = "other"  # another admin's edit lands
        db.commit()
        db.close()
        return real(project_id, path, key)

    monkeypatch.setattr(credentials_router, "read_reference", racing)
    raced = client.patch(f"/api/credentials/{refs['ssh']}", json={"store_path": "web/ssh2"})
    assert raced.status_code == 409 and "changed while" in raced.text
    db = get_sessionmaker()()
    row = db.get(Credential, refs["ssh"])
    assert (row.store_path, row.store_key) == ("web/ssh", "other")
    db.close()
