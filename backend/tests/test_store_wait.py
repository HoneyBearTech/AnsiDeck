"""While the secret store is down, runs and refreshes that need it wait in the queue instead of
failing (app.store_outage, SECRETS_STORE_WAIT_MINUTES): back in the queue in their old place
and without a run-log line, held while the outage is, failed once their wait is over, and
started once a read works again. Others don't wait."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app import main, secret_store
from app.config import get_settings
from app.db import get_sessionmaker
from app.inventory_sources import enqueue_refresh
from app.models import Inventory, InventoryRefresh, Run, SecretStoreOutage
from tests.conftest import internal_client
from tests.test_credentials import _generate_key_pem
from tests.test_inventory_refresh_protocol import CLAIM, SOURCE
from tests.test_runs import (
    SUCCESS_PLAYBOOK,
    _create_credential,
    _create_inventory_with_host,
    _create_playbook,
    _login,
)
from tests.test_secret_store import store  # noqa: F401 - the mocked secret store fixture

pytestmark = pytest.mark.no_worker  # these tests play the worker themselves

DATA = "/v1/secret/data/ansideck/1/"
SEALED = (503, {"errors": ["Vault is sealed"]})


def _sql(statement: str) -> None:
    with get_sessionmaker()() as db:
        db.execute(text(statement))
        db.commit()


def _run(run_id: int) -> Run:
    with get_sessionmaker()() as db:
        return db.get(Run, run_id)


def _outage() -> SecretStoreOutage | None:
    with get_sessionmaker()() as db:
        return db.get(SecretStoreOutage, 1)


def _claim(kinds=("run",)):
    return internal_client().post(
        "/internal/claim",
        json={"worker_id": "w", "wait_seconds": 0, "kinds": list(kinds), "host_keys": True},
    )


def _job(claim: dict):
    return internal_client().post(
        f"/internal/runs/{claim['run_id']}/job",
        json={"job_token": claim["job_token"]},
        headers={"X-Claim-Token": claim["claim_token"]},
    )


def _queue(client: TestClient, tmp_path, name: str, credential_id: int) -> int:
    inventory_id, _ = _create_inventory_with_host(client, str(tmp_path / name), name=name)
    response = client.post(
        "/api/runs",
        json={
            "playbook_id": _create_playbook(client, SUCCESS_PLAYBOOK, name=f"{name}.yml"),
            "inventory_id": inventory_id,
            "credential_id": credential_id,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def _stored_key(client: TestClient, store) -> int:  # noqa: F811
    store["secrets"][DATA + "web/ssh"] = {"private_key": _generate_key_pem()}
    response = client.post("/api/credentials", json={"name": "stored", "store_path": "web/ssh"})
    assert response.status_code == 201, response.text
    return response.json()["id"]


def test_a_run_waits_for_the_store_and_starts_once_it_is_back(
    client: TestClient,
    store,  # noqa: F811
    tmp_path,
) -> None:
    _login(client)
    waiting = _queue(client, tmp_path, "a", _stored_key(client, store))
    queued_at = _run(waiting).queued_at
    store["status"][DATA + "web/ssh"] = SEALED

    claim = _claim().json()
    assert claim["run_id"] == waiting
    assert _job(claim).status_code == 410
    row = _run(waiting)
    assert row.status == "queued" and row.queued_at == queued_at
    assert (row.claimed_at, row.worker_id, row.claim_token_hash, row.job_token_hash) == (None,) * 4
    assert row.log_seq == 0 and row.status_reason is None  # no run-log line: see requeue_run
    assert row.secret_reads is None and row.started_at is None
    assert _outage().kind == "sealed"

    reason = client.get(f"/api/runs/{waiting}").json()["waiting_reason"]
    assert reason.startswith("Waiting for OpenBao: the secret store is sealed (for 1 min).")
    assert (
        "tries again every 30 s; the run fails if OpenBao is still unavailable in 15 min" in reason
    )
    assert _claim().status_code == 204  # held while the outage is

    # A run that doesn't need the store isn't held.
    other = _queue(client, tmp_path, "b", _create_credential(client, name="here"))
    claim = _claim().json()
    assert claim["run_id"] == other and _job(claim).status_code == 200

    # The hold lapses (no sighting for 30 s): tried again, and now the store answers.
    del store["status"][DATA + "web/ssh"]
    _sql("UPDATE secret_store_outage SET hold_until = now() - interval '1 second'")
    claim = _claim().json()
    assert claim["run_id"] == waiting
    assert _job(claim).status_code == 200
    assert _outage() is None  # a job that read the store ends the outage
    assert _run(waiting).status == "running"


def test_a_run_fails_once_its_wait_is_over(
    client: TestClient,
    store,  # noqa: F811
    tmp_path,
) -> None:
    _login(client)
    run_id = _queue(client, tmp_path, "a", _stored_key(client, store))
    store["status"][DATA + "web/ssh"] = SEALED
    assert _job(_claim().json()).status_code == 410

    # 16 minutes later (it was queued before the outage began): no longer held.
    _sql("UPDATE runs SET queued_at = queued_at - interval '16 minutes'")
    _sql("UPDATE secret_store_outage SET since = since - interval '16 minutes'")
    reason = client.get(f"/api/runs/{run_id}").json()["waiting_reason"]
    assert not reason.startswith("Waiting for OpenBao")
    claim = _claim().json()
    assert claim["run_id"] == run_id
    assert _job(claim).status_code == 410
    row = _run(run_id)
    assert row.status == "failed"
    assert row.status_reason == (
        "not run: could not read credential 'stored' from OpenBao: the secret store is sealed "
        "(still unavailable after waiting 15 minutes)"
    )


def test_the_wait_counts_from_when_the_outage_began_if_later(
    client: TestClient,
    store,  # noqa: F811
    tmp_path,
) -> None:
    _login(client)
    run_id = _queue(client, tmp_path, "a", _stored_key(client, store))
    store["status"][DATA + "web/ssh"] = SEALED
    _sql("UPDATE runs SET queued_at = queued_at - interval '1 hour'")  # queued long ago
    assert _job(_claim().json()).status_code == 410
    assert _run(run_id).status == "queued"  # the outage just began: it still waits
    assert _claim().status_code == 204


def test_without_waiting_or_for_other_errors_a_run_fails_at_once(
    client: TestClient,
    store,  # noqa: F811
    tmp_path,
    monkeypatch,
) -> None:
    _login(client)
    credential = _stored_key(client, store)
    missing = _queue(client, tmp_path, "a", credential)
    store["status"][DATA + "web/ssh"] = (404, {"errors": []})  # one bad reference, no outage
    assert _job(_claim().json()).status_code == 410
    assert _run(missing).status == "failed" and _outage() is None

    monkeypatch.setenv("SECRETS_STORE_WAIT_MINUTES", "0")
    get_settings.cache_clear()
    store["status"][DATA + "web/ssh"] = SEALED
    sealed = _queue(client, tmp_path, "b", credential)
    assert _job(_claim().json()).status_code == 410
    row = _run(sealed)
    assert row.status == "failed"
    assert row.status_reason.endswith("from OpenBao: the secret store is sealed")
    get_settings.cache_clear()


def test_the_probe_holds_and_ends_the_outage(store, monkeypatch) -> None:  # noqa: F811
    answers = iter(
        [
            {"ok": False, "error_kind": "unreachable"},
            {"ok": False, "error_kind": "denied"},  # not an outage: changes nothing
            {"ok": True, "error_kind": None},
        ]
    )
    monkeypatch.setattr(secret_store, "probe", lambda: next(answers))
    assert main._probe_secret_store() is False
    assert _outage().kind == "unreachable"
    assert main._probe_secret_store() is False
    assert _outage().kind == "unreachable"
    assert main._probe_secret_store() is True
    assert _outage() is None


def test_the_status_shows_the_wait_and_the_outage(client: TestClient, store) -> None:  # noqa: F811
    _login(client)
    status = client.get("/api/secret-store/status").json()
    assert (status["wait_minutes"], status["outage_kind"]) == (15, None)
    with get_sessionmaker()() as db:
        from app import store_outage

        store_outage.seen(db, "sealed")
        db.commit()
    status = client.get("/api/secret-store/status").json()
    assert status["outage_kind"] == "sealed" and status["outage_since"]


def _store_source(client: TestClient, store) -> int:  # noqa: F811
    """An inventory with a source whose env credential is in the store."""
    store["secrets"][DATA + "cloud/netbox"] = {"NETBOX_TOKEN": "tok-sentinel"}
    credential = client.post(
        "/api/credentials", json={"name": "nb", "kind": "env", "store_path": "cloud/netbox"}
    ).json()["id"]
    inventory_id = client.post("/api/inventories", json={"name": "dyn"}).json()["id"]
    response = client.post(
        f"/api/inventories/{inventory_id}/sources",
        json={"name": "gen", "config": SOURCE, "credential_id": credential},
    )
    assert response.status_code == 201, response.text
    return inventory_id


def _refresh_job():
    http = internal_client()
    claim = http.post("/internal/claim", json=CLAIM)
    if claim.status_code != 200:
        return claim, None
    body = claim.json()
    job = http.post(
        f"/internal/refreshes/{body['run_id']}/job",
        json={"job_token": body["job_token"]},
        headers={"X-Claim-Token": body["claim_token"]},
    )
    return job, body["run_id"]


def test_a_refresh_waits_too_and_merges_into_one_queued_meanwhile(
    client: TestClient,
    store,  # noqa: F811
) -> None:
    _login(client)
    inventory_id = _store_source(client, store)
    store["status"][DATA + "cloud/netbox"] = SEALED
    run = client.post(
        "/api/runs",
        json={
            "playbook_id": _create_playbook(client, SUCCESS_PLAYBOOK),
            "inventory_id": inventory_id,
            "credential_id": _create_credential(client, name="here"),
            "refresh_first": True,
        },
    ).json()
    first = _run(run["id"]).waiting_refresh_id

    job, refresh_id = _refresh_job()
    assert (job.status_code, refresh_id) == (410, first)
    with get_sessionmaker()() as db:
        refresh = db.get(InventoryRefresh, first)
        assert (refresh.status, refresh.claimed_at, refresh.error) == ("queued", None, None)
    assert _refresh_job()[0].status_code == 204  # held
    assert _claim().status_code == 204  # the run still waits for its refresh

    # Claimed again once the hold lapses, while another refresh was queued meanwhile.
    _sql("UPDATE secret_store_outage SET hold_until = now() - interval '1 second'")
    http = internal_client()
    claim = http.post("/internal/claim", json=CLAIM).json()
    assert claim["run_id"] == first
    with get_sessionmaker()() as db:
        second = enqueue_refresh(db, db.get(Inventory, inventory_id), "schedule", source_ids=[])
        db.commit()
    job = http.post(
        f"/internal/refreshes/{first}/job",
        json={"job_token": claim["job_token"]},
        headers={"X-Claim-Token": claim["claim_token"]},
    )
    assert job.status_code == 410
    with get_sessionmaker()() as db:
        merged = db.get(InventoryRefresh, first)
        kept = db.get(InventoryRefresh, second)
        assert merged.status == "cancelled"
        assert merged.error == f"merged into refresh #{second} while waiting for OpenBao"
        assert kept.status == "queued" and kept.scope is None  # [] widened to every source
        assert kept.queued_at == merged.queued_at  # it keeps the older place
    assert _run(run["id"]).waiting_refresh_id == second  # the run waits for that one now


@pytest.mark.parametrize("needs", ["vault_password", "env_credential"])
def test_a_vault_password_or_variables_in_the_store_make_a_run_wait(
    client: TestClient,
    store,  # noqa: F811
    tmp_path,
    needs: str,
) -> None:
    _login(client)
    store["secrets"][DATA + "x"] = (
        {"password": "pw"} if needs == "vault_password" else {"TOKEN": "t"}
    )
    body = {}
    if needs == "vault_password":
        vault = client.post("/api/vault-passwords", json={"name": "v", "store_path": "x"})
        body["vault_password_id"] = vault.json()["id"]
    else:
        env = client.post("/api/credentials", json={"name": "e", "kind": "env", "store_path": "x"})
        here = client.post(
            "/api/credentials", json={"name": "e2", "kind": "env", "env": {"A": "1"}}
        )
        body["env_credential_ids"] = [here.json()["id"], env.json()["id"]]
    inventory_id, _ = _create_inventory_with_host(client, str(tmp_path / "m"))
    run = client.post(
        "/api/runs",
        json={
            "playbook_id": _create_playbook(client, SUCCESS_PLAYBOOK),
            "inventory_id": inventory_id,
            "credential_id": _create_credential(client, name="here"),
            **body,
        },
    )
    assert run.status_code == 201, run.text
    store["status"][DATA + "x"] = SEALED
    assert _job(_claim().json()).status_code == 410
    assert _run(run.json()["id"]).status == "queued"
    assert _claim().status_code == 204
    assert (
        client.get(f"/api/runs/{run.json()['id']}")
        .json()["waiting_reason"]
        .startswith("Waiting for OpenBao")
    )
