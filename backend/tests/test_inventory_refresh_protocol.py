"""Inventory refreshes over the internal API (Phase 4G-2), with the test playing the worker:
claims by kind, the one-time job (one call per source), chunked outputs per part, the sources'
report and the combine job, the API's checks of untrusted output, the reaper, the schedule and
the galaxy gate."""

import hashlib
import json
from datetime import datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text, update

from app.db import get_engine, get_sessionmaker
from app.galaxy import try_start_install
from app.inventory_sources import SourceError, check_config, normalise, prune_snapshots
from app.models import (
    GalaxyInstall,
    Inventory,
    InventoryRefresh,
    InventorySnapshot,
    Run,
    RunStatus,
)
from app.reaper import reap_once
from tests.conftest import internal_client
from tests.test_runs import SUCCESS_PLAYBOOK, _create_credential, _create_playbook, _login

pytestmark = pytest.mark.no_worker  # these tests play the worker themselves

SOURCE = "plugin: ansible.builtin.generator\nhosts:\n  name: gen\n"
CONSTRUCTED = "plugin: ansible.builtin.constructed\nkeyed_groups:\n  - key: role\n"


def _output(hosts: dict, groups: dict | None = None) -> bytes:
    """ansible-inventory --list --export as it would print them."""
    data = {"_meta": {"hostvars": hosts, "profile": "inventory_legacy"}}
    data["all"] = {"children": ["ungrouped", *(groups or {})]}
    data.update(groups or {})
    return json.dumps(data).encode()


def _setup(client: TestClient, *, env: dict | None = None) -> int:
    _login(client)
    inventory_id = client.post("/api/inventories", json={"name": "dyn"}).json()["id"]
    client.post(
        f"/api/inventories/{inventory_id}/hosts",
        json={"hostname": "static1", "vars": {"role": "web"}},
    )
    credential_id = None
    if env:
        credential_id = client.post(
            "/api/credentials", json={"name": "env", "kind": "env", "env": env}
        ).json()["id"]
    for name, config in (("late", CONSTRUCTED), ("gen", SOURCE)):
        response = client.post(
            f"/api/inventories/{inventory_id}/sources",
            json={"name": name, "config": config, "credential_id": credential_id},
        )
        assert response.status_code == 201, response.text
    return inventory_id


CLAIM = {"worker_id": "w", "wait_seconds": 0, "kinds": ["refresh"], "partial_refreshes": True}


def _result(source_id: int, data: bytes) -> dict:
    return {
        "source_id": source_id,
        "status": "success",
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


class ClaimedRefresh:
    def __init__(self) -> None:
        self.http = internal_client()
        self.calls: list[dict] = []
        claim = self.http.post("/internal/claim", json=CLAIM)
        assert claim.status_code == 200, claim.text
        body = claim.json()
        assert body["kind"] == "refresh"
        self.id, self.claim_token, self.job_token = (
            body["run_id"],
            body["claim_token"],
            body["job_token"],
        )

    def post(self, action: str, body: dict, claim_token: str | None = None):
        return self.http.post(
            f"/internal/refreshes/{self.id}/{action}",
            json=body,
            headers={"X-Claim-Token": claim_token or self.claim_token},
        )

    def job(self):
        response = self.post("job", {"job_token": self.job_token})
        if response.status_code == 200:
            self.calls = response.json()["calls"]
        return response

    @property
    def source_id(self) -> int:
        """The (one) source this job runs."""
        return int(self.calls[0]["key"][1:])

    def upload(self, data: bytes, offset: int = 0, part: str | None = None):
        return self.http.post(
            f"/internal/refreshes/{self.id}/output",
            content=data,
            headers={
                "X-Claim-Token": self.claim_token,
                "X-Offset": str(offset),
                "X-Part": part or f"s{self.source_id}",
            },
        )

    def report(self, data: bytes):
        """Uploads the source's output and reports it; the API's answer."""
        assert self.upload(data).status_code == 200
        return self.post("sources", {"results": [_result(self.source_id, data)]})

    def finish(self, data: bytes):
        """The source found `data`, and the combine (the constructed source) gives the same."""
        answer = self.report(data)
        assert answer.status_code == 200, answer.text
        assert "combine" in answer.json()
        assert self.upload(data, part="combined").status_code == 200
        return self.post(
            "complete",
            {"status": "success", "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()},
        )

    def row(self) -> InventoryRefresh:
        db = get_sessionmaker()()
        try:
            return db.get(InventoryRefresh, self.id)
        finally:
            db.close()


def test_only_workers_that_ask_for_refreshes_get_them(client: TestClient) -> None:
    _setup(client)
    http = internal_client()
    old = http.post("/internal/claim", json={"worker_id": "old", "wait_seconds": 0})
    assert old.status_code == 204  # a worker from before 4G never gets a refresh
    whole = http.post("/internal/claim", json={**CLAIM, "partial_refreshes": False})
    assert whole.status_code == 204  # nor one that runs every source in one call
    claimed = ClaimedRefresh()
    assert claimed.row().status == "running"


def test_the_refresh_job_is_handed_out_once_in_order_with_its_variables(
    client: TestClient,
) -> None:
    _setup(client, env={"NB_TOKEN": "nb-job-sentinel"})
    claimed = ClaimedRefresh()
    assert claimed.post("job", {"job_token": claimed.job_token}, "stale").status_code == 410
    assert claimed.post("job", {"job_token": "guess"}).status_code == 410
    job = claimed.job()
    assert job.status_code == 200, job.text
    body = job.json()
    # Stage one: the generator alone (the constructed source waits for the combine).
    assert [call["kind"] for call in body["calls"]] == ["plugin"]
    (call,) = body["calls"]
    assert [f["name"] for f in call["files"]] == [f"10-src{claimed.source_id}.generator.yml"]
    assert call["env"] == {"NB_TOKEN": "nb-job-sentinel"}
    assert body["secrets"] == ["nb-job-sentinel"]
    assert body["timeout_seconds"] == 300
    assert claimed.row().started_at is not None and claimed.row().stage == "sources"
    assert claimed.job().status_code == 410  # single use

    answer = claimed.report(_output({"gen": {"role": "db"}}))
    combine = answer.json()["combine"]
    (call,) = combine["calls"]
    names = [f["name"] for f in call["files"]]
    assert names[0] == f"100-src{claimed.source_id}.out.yml" and names[1] == "500-static.yml"
    assert names[2].endswith(".constructed.yml")  # constructed last, whatever its position
    assert "!unsafe 'db'" in call["files"][0]["text"] or "!unsafe db" in call["files"][0]["text"]
    assert "static1" in call["files"][1]["text"]
    assert call["kind"] == "combine" and call["env"] == {"NB_TOKEN": "nb-job-sentinel"}
    assert combine["secrets"] == ["nb-job-sentinel"]
    assert claimed.row().stage == "combine"
    again = claimed.post("sources", {"results": []})  # asked again: the same job
    assert again.json()["combine"]["calls"][0]["files"] == call["files"]


def test_output_is_appended_by_offset_and_checked_before_it_counts(client: TestClient) -> None:
    _setup(client)
    claimed = ClaimedRefresh()
    claimed.job()
    data = _output({"h1": {"x": 1}, "static1": {"role": "web"}})
    assert claimed.upload(data[:10]).json() == {"offset": 10}
    gap = claimed.upload(data[20:], offset=20)
    assert gap.status_code == 409 and gap.json() == {"expected_offset": 10}
    assert claimed.upload(data[:10]).json() == {"offset": 10}  # a resent chunk is fine
    assert claimed.upload(data[10:], offset=10).status_code == 200
    assert claimed.upload(b"{}", part="s999999").status_code == 409  # not a source it ran
    assert claimed.upload(b"{}", part="combined").status_code == 409  # not yet
    early = claimed.post("complete", {"status": "success", "bytes": 2, "sha256": "0" * 64})
    assert early.status_code == 409  # the sources first
    wrong = claimed.post(
        "sources", {"results": [{**_result(claimed.source_id, data), "sha256": "0" * 64}]}
    )
    assert wrong.status_code == 409
    other = claimed.post("sources", {"results": [_result(999999, data)]})
    assert other.status_code == 409
    assert (
        claimed.post("sources", {"results": [_result(claimed.source_id, data)]}).status_code == 200
    )
    assert claimed.upload(data, part="combined").status_code == 200
    wrong = claimed.post("complete", {"status": "success", "bytes": len(data), "sha256": "0" * 64})
    assert wrong.status_code == 409
    done = claimed.post(
        "complete",
        {"status": "success", "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()},
    )
    assert done.status_code == 200
    row = claimed.row()
    assert row.status == "success" and row.snapshot_id is not None and row.output_bytes == len(data)
    db = get_sessionmaker()()
    inventory = db.get(Inventory, row.inventory_id)
    snapshot = db.get(InventorySnapshot, inventory.current_snapshot_id)
    assert snapshot.data["static_hosts"] == ["static1"] and snapshot.host_count == 2
    db.close()
    assert claimed.upload(b"more").status_code == 410  # the claim ended


def test_hostile_output_is_normalised_or_refused(client: TestClient) -> None:
    _setup(client)
    claimed = ClaimedRefresh()
    claimed.job()
    data = _output(
        {
            "ok1": {"note": {"__ansible_unsafe": "{{ lookup('pipe', 'id') }}"}},
            "db:5432": {},
            "v1": {"secret": {"__ansible_vault": "$ANSIBLE_VAULT;1.1;AES256\n..."}},
        },
        {"all_in": {"hosts": ["ok1", "db:5432"], "children": []}, "bad name": {"hosts": []}},
    )
    assert claimed.finish(data).status_code == 200
    db = get_sessionmaker()()
    snapshot = db.get(InventorySnapshot, claimed.row().snapshot_id)
    db.close()
    assert sorted(snapshot.data["hosts"]) == ["ok1", "v1"]
    assert snapshot.data["hosts"]["ok1"]["note"] == "{{ lookup('pipe', 'id') }}"
    assert snapshot.data["hosts"]["v1"] == {}
    assert snapshot.data["groups"] == {"all_in": {"hosts": ["ok1"], "children": [], "vars": {}}}
    # The port, the vault value, the group name: found when the source's output was stored (the
    # combine here repeats the same raw output, so it finds them again).
    from_source = [w for w in snapshot.warnings if w.startswith("source 'gen': ")]
    assert len(from_source) == 3

    cyclic = _output({}, {"a": {"children": ["b"]}, "b": {"children": ["a"]}})
    client.post(f"/api/inventories/{claimed.row().inventory_id}/refresh")
    again = ClaimedRefresh()
    again.job()
    assert again.finish(cyclic).status_code == 200
    assert again.row().status == "failed" and "contains itself" in again.row().error


@pytest.mark.parametrize(
    ("raw", "message"),
    [  # short ids: a 100k-character test id once stalled CI's verbose log
        pytest.param(b"not json", "not valid JSON", id="not-json"),
        pytest.param(
            json.dumps({"_meta": {"profile": "other"}}).encode(), "format", id="other-profile"
        ),
        pytest.param(
            json.dumps({"_meta": {"profile": "inventory_legacy"}, "g": []}).encode(),
            "unexpected",
            id="group-not-a-mapping",
        ),
        # refused before json.loads would recurse into it
        pytest.param(b"[" * 100_000, "nested deeper", id="deep-nesting"),
        pytest.param(
            b'{"_meta": {"profile": "inventory_legacy"}, "x": "[[[[[[[["}',
            "unexpected",
            id="brackets-in-a-string",
        ),
        # names that aren't strings: refused, not a TypeError (a 500, and a refresh left to
        # run until its lease expired)
        *(
            pytest.param(
                json.dumps({"_meta": {"profile": "inventory_legacy"}, **groups}).encode(),
                "unexpected",
                id=case,
            )
            for case, groups in (
                ("list-host", {"g": {"hosts": [["a"]]}}),
                ("dict-host", {"g": {"hosts": [{"a": 1}]}}),
                ("int-host", {"g": {"hosts": [7]}}),
                ("dict-child", {"g": {"children": [{"a": 1}]}}),
                ("ungrouped-list-host", {"ungrouped": {"hosts": [["a"]]}}),
                ("ungrouped-int", {"ungrouped": {"hosts": 7}}),
                ("ungrouped-string", {"ungrouped": {"hosts": "abc"}}),
            )
        ),
    ],
)
def test_the_normaliser_refuses_what_it_cannot_trust(raw: bytes, message: str) -> None:
    with pytest.raises(SourceError, match=message):
        normalise(raw, [])


def test_the_normaliser_enforces_its_limits(monkeypatch) -> None:
    from app.config import get_settings

    monkeypatch.setenv("INVENTORY_MAX_HOSTS", "2")
    get_settings.cache_clear()
    try:
        with pytest.raises(SourceError, match="more than 2 hosts"):
            normalise(_output({"a": {}, "b": {}, "c": {}}), [])
        deep: dict = {}
        node = deep
        for _ in range(40):
            node["x"] = {}
            node = node["x"]
        with pytest.raises(SourceError, match="nested deeper"):
            normalise(_output({"a": deep}), [])
    finally:
        get_settings.cache_clear()


def test_the_reaper_ends_a_refresh_whose_worker_went_away(client: TestClient) -> None:
    _setup(client)
    claimed = ClaimedRefresh()
    claimed.job()
    renewed = internal_client().post(
        "/internal/heartbeat",
        json={
            "worker_id": "w",
            "runs": [],
            "refreshes": [{"refresh_id": claimed.id, "claim_token": claimed.claim_token}],
        },
    )
    assert renewed.json()["refreshes"] == [{"refresh_id": claimed.id, "state": "ok"}]
    with get_engine().begin() as conn:
        conn.execute(
            update(InventoryRefresh)
            .where(InventoryRefresh.id == claimed.id)
            .values(lease_expires_at=text("now() - interval '1 second'"))
        )
    reap_once()
    row = claimed.row()
    assert row.status == "failed" and row.error.startswith("worker lost")
    assert claimed.upload(b"{}").status_code == 410
    gone = internal_client().post(
        "/internal/heartbeat",
        json={
            "worker_id": "w",
            "runs": [],
            "refreshes": [{"refresh_id": claimed.id, "claim_token": claimed.claim_token}],
        },
    )
    assert gone.json()["refreshes"] == [{"refresh_id": claimed.id, "state": "gone"}]


def test_galaxy_installs_and_refreshes_wait_for_each_other(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr("app.galaxy.run_install", lambda install_id: None)
    _setup(client)
    claimed = ClaimedRefresh()
    db = get_sessionmaker()()
    install = GalaxyInstall(
        status=RunStatus.QUEUED.value, triggered_by="admin", requirements_snapshot=""
    )
    db.add(install)
    db.commit()
    assert try_start_install() is None  # a refresh is running: plugins load collections
    db.execute(update(InventoryRefresh).values(status="success", claim_token_hash=None))
    db.commit()
    assert try_start_install() == install.id
    db.close()
    client.post(f"/api/inventories/{claimed.row().inventory_id}/refresh")
    blocked = internal_client().post("/internal/claim", json=CLAIM)
    assert blocked.status_code == 204  # nothing is claimed while an install runs


def test_refreshes_are_scheduled_and_merged(client: TestClient) -> None:
    inventory_id = _setup(client)

    def queued() -> list[str]:
        db = get_sessionmaker()()
        try:
            return list(
                db.scalars(
                    select(InventoryRefresh.trigger).where(
                        InventoryRefresh.status == "queued",
                        InventoryRefresh.inventory_id == inventory_id,
                    )
                )
            )
        finally:
            db.close()

    assert queued() == ["sources_changed"]  # adding the second source merged into it
    client.post(f"/api/inventories/{inventory_id}/hosts", json={"hostname": "new", "vars": {}})
    assert queued() == ["sources_changed"]  # still one
    ClaimedRefresh()  # running now
    client.post(f"/api/inventories/{inventory_id}/hosts", json={"hostname": "new2", "vars": {}})
    assert queued() == ["static_changed"]

    settings = client.put(
        f"/api/inventories/{inventory_id}/refresh-settings", json={"refresh_interval_seconds": 60}
    )
    assert settings.status_code == 422  # at most every 300 s
    client.put(
        f"/api/inventories/{inventory_id}/refresh-settings",
        json={"refresh_interval_seconds": 300},
    )
    db = get_sessionmaker()()
    db.execute(update(InventoryRefresh).values(status="success", claim_token_hash=None))
    db.execute(update(InventoryRefresh).values(queued_at=text("now() - interval '10 minutes'")))
    db.commit()
    db.close()
    reap_once()
    assert queued() == ["schedule"]


def test_a_run_pins_the_snapshot_and_pruning_keeps_it(client: TestClient) -> None:
    inventory_id = _setup(client)
    playbook_id = _create_playbook(client, SUCCESS_PLAYBOOK)
    credential_id = _create_credential(client)
    body = {
        "playbook_id": playbook_id,
        "inventory_id": inventory_id,
        "credential_id": credential_id,
    }
    early = client.post("/api/runs", json=body)
    assert early.status_code == 409 and "haven't been refreshed" in early.json()["detail"]

    claimed = ClaimedRefresh()
    claimed.job()
    claimed.finish(_output({"first": {}}, {"g": {"hosts": ["first"]}}))
    run = client.post("/api/runs", json={**body, "group_name": "g"})
    assert run.status_code == 201, run.text
    for n in range(7):  # newer snapshots supersede the pinned one
        client.post(f"/api/inventories/{inventory_id}/refresh")
        later = ClaimedRefresh()
        later.job()
        later.finish(_output({f"h{n}": {}}))
    db = get_sessionmaker()()
    pinned = db.get(Run, run.json()["id"]).inventory_snapshot_id
    prune_snapshots(db)
    db.commit()
    kept = set(db.scalars(select(InventorySnapshot.id)))
    db.close()
    assert pinned in kept and len(kept) == 6  # the current one, 4 more, and the pinned one


def test_a_run_keeps_what_its_snapshot_was_after_it_is_pruned(client: TestClient) -> None:
    inventory_id = _setup(client)
    body = {
        "playbook_id": _create_playbook(client, SUCCESS_PLAYBOOK),
        "inventory_id": inventory_id,
        "credential_id": _create_credential(client),
    }
    claimed = ClaimedRefresh()
    claimed.job()
    claimed.finish(_output({"a": {}, "b": {}, "c": {}}))
    created = client.post("/api/runs", json=body).json()
    db = get_sessionmaker()()
    snapshot = db.get(InventorySnapshot, db.get(Run, created["id"]).inventory_snapshot_id)
    assert created["inventory_snapshot_hosts"] == snapshot.host_count == 3
    assert datetime.fromisoformat(created["inventory_snapshot_at"]) == snapshot.created_at
    db.delete(snapshot)  # as pruning does, once nothing queued or running pins it
    db.commit()
    db.close()
    run = client.get(f"/api/runs/{created['id']}").json()
    assert (run["inventory_snapshot_at"], run["inventory_snapshot_hosts"]) == (
        created["inventory_snapshot_at"],
        3,
    )


def test_a_run_on_an_inventory_without_sources_has_no_snapshot(client: TestClient) -> None:
    _login(client)
    inventory_id = client.post("/api/inventories", json={"name": "plain"}).json()["id"]
    run = client.post(
        "/api/runs",
        json={
            "playbook_id": _create_playbook(client, SUCCESS_PLAYBOOK),
            "inventory_id": inventory_id,
            "credential_id": _create_credential(client),
        },
    ).json()
    assert (run["inventory_snapshot_at"], run["inventory_snapshot_hosts"]) == (None, None)


def test_source_configs_and_credentials_are_checked(client: TestClient) -> None:
    _login(client)
    inventory_id = client.post("/api/inventories", json={"name": "chk"}).json()["id"]
    ssh = _create_credential(client)
    env = client.post(
        "/api/credentials", json={"name": "e", "kind": "env", "env": {"T": "x"}}
    ).json()["id"]

    def create(config: str, **extra):
        return client.post(
            f"/api/inventories/{inventory_id}/sources",
            json={"name": "s", "config": config, **extra},
        )

    for config, message in (
        ("plugin: auto", "can't be used"),
        ("plugin: ansible.builtin.script", "can't be used"),
        ("plugin: ini", "can't be used"),
        ("plugin: netbox.netbox.nb_inventory\ntoken: abc", "literal value"),
        ("plugin: constructed\ncache: true", "'cache' must be off"),
        ("- a list", "mapping"),
        ("plugin: '../x'", "must name an inventory plugin"),
    ):
        response = create(config)
        assert response.status_code == 400 and message in response.json()["detail"], config
    assert create(SOURCE, credential_id=ssh).status_code == 400  # an SSH key isn't variables
    source = create(SOURCE, credential_id=env)
    assert source.status_code == 201
    deleted = client.delete(f"/api/credentials/{env}")
    assert deleted.status_code == 409 and "uses this credential" in deleted.json()["detail"]


@pytest.mark.parametrize(
    "plugin",
    ["script", "ansible.builtin.script", "ansible.legacy.script", "ansible.legacy.ini",
     "ansible.legacy.host_list", "ansible.legacy.auto"],
)  # fmt: skip
def test_denied_plugins_are_refused_under_every_name(plugin: str) -> None:
    with pytest.raises(SourceError, match="can't be used as a source"):
        check_config(f"plugin: {plugin}\n")
