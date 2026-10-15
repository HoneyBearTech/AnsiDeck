"""Refreshes run each source on its own (app.inventory_sources, app.run_worker): every call has
only its own credential, home and config; the API's combine of the sources' outputs equals
ansible-inventory reading them all at once; the constructed stage never templates a source's
strings; a failed source keeps its last good output; and an inventory refreshed before this
change keeps its snapshot rather than lose a failed source's hosts."""

import json
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import run_worker
from app.db import get_sessionmaker
from app.inventory_render import mark_unsafe, merge, render
from app.inventory_sources import (
    _layer,
    _legacy_json,
    keep_current_snapshot,
    normalise,
    parse_output,
)
from app.models import (
    Inventory,
    InventoryRefreshSource,
    InventorySnapshot,
    InventorySource,
    InventorySourceOutput,
)
from tests.test_inventory_refresh_protocol import CONSTRUCTED, ClaimedRefresh, _output, _setup
from tests.test_inventory_sources import _add_source, _inventory, _wait_refresh
from tests.test_runs import _login

ANSIBLE_INVENTORY = str(Path(sys.executable).parent / "ansible-inventory")


def _calls(job: dict) -> dict[str, dict]:
    """What run_worker.run_inventory sends back, by call."""
    results: dict[str, dict] = {}
    output: list[str] = []

    def emit(message: dict) -> None:
        if message["type"] == "output":
            output.append(message["data"])
        elif message["type"] == "inventory_result":
            results[message["key"]] = {
                "rc": message["rc"],
                "stderr": message["stderr"],
                "output": json.loads("".join(output)) if message["rc"] == 0 else None,
            }
            output.clear()

    run_worker.run_inventory({"max_output_bytes": 10**7, **job}, emit)
    return results


def _hosts(result: dict) -> list[str]:
    return sorted(result["output"]["_meta"]["hostvars"]) + sorted(
        result["output"].get("ungrouped", {}).get("hosts", [])
    )


WHO = (
    "plugin: ansible.builtin.generator\nhosts:\n  name: "
    "\"{{ lookup('env', 'A') | default('none', true) }}-"
    "{{ lookup('env', 'B') | default('none', true) }}-"
    "{{ lookup('env', 'HOME') | dirname | basename }}-"
    "{{ lookup('env', 'ANSIBLE_CONFIG') | dirname | basename }}-{{ x }}\"\n"
    "layers:\n  x: [h]\n"
)


def test_each_source_runs_alone_with_only_its_own_credential() -> None:
    results = _calls(
        {
            "calls": [
                {
                    "key": "s1",
                    "kind": "plugin",
                    "files": [{"name": "10-src1.generator.yml", "text": WHO}],
                    "env": {"A": "alpha"},
                },
                {
                    "key": "s2",
                    "kind": "plugin",
                    "files": [{"name": "10-src2.generator.yml", "text": WHO}],
                    "env": {"B": "beta"},
                },
            ]
        }
    )
    # Each call sees only its own variables, a home and an (empty) ansible.cfg of its own.
    assert _hosts(results["s1"]) == ["alpha-none-c0-c0-h"]
    assert _hosts(results["s2"]) == ["none-beta-c1-c1-h"]


def test_a_source_is_only_ever_read_as_a_plugin_config() -> None:
    inventory_file = "all:\n  hosts:\n    planted:\n      ansible_connection: local\n"
    results = _calls(
        {
            "calls": [
                {
                    "key": "s1",
                    "kind": "plugin",
                    "files": [{"name": "10-src1.yml", "text": inventory_file}],
                    "env": {},
                }
            ]
        }
    )
    assert results["s1"]["rc"] != 0  # not a plugin config: the yaml plugin isn't enabled


def test_an_unknown_kind_of_call_is_refused() -> None:
    with pytest.raises(RuntimeError, match="invalid inventory call"):
        _calls({"calls": [{"key": "s1", "kind": "script", "files": [], "env": {}}]})


def _ansible(tmp: Path, files: dict[str, str]) -> bytes:
    paths = []
    for name, text in files.items():
        (tmp / name).write_text(text)
        paths += ["-i", str(tmp / name)]
    env = {"PATH": f"{Path(sys.executable).parent}:/usr/bin:/bin", "HOME": str(tmp)}
    env.update(run_worker.INVENTORY_ENV, ANSIBLE_INVENTORY_ENABLED="auto,yaml")
    result = subprocess.run(
        [ANSIBLE_INVENTORY, *paths, "--list", "--export"],
        capture_output=True,
        cwd=tmp,
        env=env,
        check=True,
        timeout=120,
    )
    return result.stdout


SOURCES = {
    "10-a.yml": """
all:
  vars: {site: a, shared: a}
  hosts:
    h1: {x: 1, role: web, ansible_port: 2201}
    h2: {x: 2}
  children:
    web:
      hosts: {h1: null, h2: null}
      vars: {tier: front, ansible_group_priority: 5}
    app:
      children: {web: null}
""",
    "11-b.yml": """
all:
  vars: {shared: b}
  hosts:
    h2: {x: 22, extra: [1, {deep: true}]}
    h3: {}
    lone: {}
    zz-lone-with-vars: {v: 1}
  children:
    empty: {}
    web:
      hosts: {h3: null, h1: null}
      vars: {tier: back}
    db:
      hosts: {h2: null}
""",
}
STATIC = {
    "hosts": {"h1": {"x": "static"}, "s1": {"role": "db"}},
    "groups": {"web": ["s1"], "own": ["h3"]},
}


def test_the_apis_combine_equals_ansible_reading_every_source_at_once(tmp_path: Path) -> None:
    static_graph = merge(STATIC)
    static_text = render(
        {
            **static_graph,
            "hosts": {n: mark_unsafe(v) for n, v in static_graph["hosts"].items()},
        }
    )
    static_hosts = list(STATIC["hosts"])
    single = _ansible(tmp_path, {**SOURCES, "50-static.yml": static_text})
    expected, expected_warnings = normalise(single, static_hosts)

    outputs = []
    for name, text in SOURCES.items():
        one = tmp_path / name.removesuffix(".yml")
        one.mkdir()
        outputs.append(parse_output(_ansible(one, {name: text}))[0])
    combined, warnings = normalise(_legacy_json(_layer([*outputs, static_graph])), static_hosts)

    assert json.dumps(combined, sort_keys=True) == json.dumps(expected, sort_keys=True)
    for name, group in expected["groups"].items():  # order matters for members and children
        assert combined["groups"][name]["hosts"] == group["hosts"], name
        assert combined["groups"][name]["children"] == group["children"], name
    assert list(combined["hosts"]) == list(expected["hosts"])
    assert sorted(warnings) == sorted(expected_warnings)


@pytest.mark.no_worker
def test_the_constructed_stage_never_templates_a_sources_strings(client: TestClient) -> None:
    _setup(client)
    claimed = ClaimedRefresh()
    claimed.job()
    found = _output({"gen": {"note": "{{ 6 * 7 }}", "role": "db"}})
    combine = claimed.report(found).json()["combine"]
    # The worker's combine, for real: the source's output, the inventory's own hosts, then
    # `keyed_groups: role` (CONSTRUCTED) and a compose over the source's string.
    (call,) = combine["calls"]
    call["files"][-1]["text"] = CONSTRUCTED + "compose:\n  seen: note\n"
    result = _calls({"calls": [call]})["combined"]
    assert result["rc"] == 0, result["stderr"]
    hostvars = result["output"]["_meta"]["hostvars"]
    seen = hostvars["gen"]["seen"]
    assert (seen.get("__ansible_unsafe") if isinstance(seen, dict) else seen) == "{{ 6 * 7 }}"
    groups = {k: v for k, v in result["output"].items() if k not in ("_meta", "all")}
    assert "gen" in groups["_db"]["hosts"], groups  # constructed still saw its vars


GENERATOR = (
    "plugin: ansible.builtin.generator\nhosts:\n  name: '{{ n }}-{{ x }}'\nlayers:\n  x: [a, b]\n"
)


def test_a_failed_source_keeps_its_last_good_output(client: TestClient) -> None:
    _login(client)
    inventory_id = _inventory(client)
    _add_source(client, inventory_id, "one", GENERATOR.replace("{{ n }}", "one"))
    other = _add_source(client, inventory_id, "two", GENERATOR.replace("{{ n }}", "two"))
    assert _wait_refresh(client, inventory_id)["status"] == "success"
    hosts = client.get(f"/api/inventories/{inventory_id}/targets").json()["hosts"]

    broken = "plugin: netbox.netbox.nb_inventory\napi_endpoint: http://127.0.0.1:1\ntoken: x\n"
    client.patch(
        f"/api/inventories/{inventory_id}/sources/{other['id']}",
        json={"config": broken.replace("token: x", "token: \"{{ lookup('env', 'T') }}\"")},
    )
    failed = _wait_refresh(client, inventory_id)
    assert failed["status"] == "failed" and failed["error"].startswith("source 'two': ")
    # Only the edited source ran; the other one contributed what it found last.
    results = {r["name"]: (r["ran"], r["status"]) for r in failed["source_results"]}
    assert results == {"one": (False, None), "two": (True, "failed")}
    # The snapshot still has every host: "two" contributes its last good output.
    assert client.get(f"/api/inventories/{inventory_id}/targets").json()["hosts"] == hosts
    sources = {s["name"]: s for s in client.get(f"/api/inventories/{inventory_id}/sources").json()}
    assert sources["two"]["last_error"] and sources["two"]["output_host_count"] == 2
    assert sources["one"]["last_error"] is None and sources["one"]["output_host_count"] == 2


def test_a_source_that_never_ran_alone_doesnt_lose_its_hosts(client: TestClient) -> None:
    """An inventory refreshed before sources ran alone: its snapshot holds a source that has no
    output of its own yet. If that source fails, the combination would lack its hosts: the
    current snapshot stays."""
    _login(client)
    inventory_id = _inventory(client)
    source = _add_source(client, inventory_id, "one", GENERATOR.replace("{{ n }}", "one"))
    assert _wait_refresh(client, inventory_id)["status"] == "success"
    db = get_sessionmaker()()
    try:
        inventory = db.get(Inventory, inventory_id)
        snapshot = db.get(InventorySnapshot, inventory.current_snapshot_id)
        assert {entry["id"] for entry in snapshot.sources} == {source["id"]}

        def row(source_id: int | None, status: str) -> InventoryRefreshSource:
            return InventoryRefreshSource(
                refresh_id=snapshot.refresh_id, source_id=source_id, name="x", plugin="x",
                ran=True, status=status,
            )  # fmt: skip

        worked = row(None, "success")  # some other source worked this time
        assert keep_current_snapshot(db, inventory, [row(source["id"], "failed")])  # none did
        failed = row(source["id"], "failed")
        assert not keep_current_snapshot(db, inventory, [failed, worked])  # its output counts
        db.delete(db.get(InventorySourceOutput, source["id"]))  # as before the upgrade
        db.flush()
        assert keep_current_snapshot(db, inventory, [failed, worked])
        other = InventorySource(
            inventory_id=inventory_id, name="new", plugin="x", config="", created_by="t"
        )
        db.add(other)
        db.flush()
        # A new source failing loses nothing (the current snapshot never had it).
        assert not keep_current_snapshot(db, inventory, [row(other.id, "failed"), worked])
    finally:
        db.rollback()
        db.close()


def test_outputs_go_with_their_source(client: TestClient) -> None:
    _login(client)
    inventory_id = _inventory(client)
    source = _add_source(client, inventory_id, "one", GENERATOR.replace("{{ n }}", "one"))
    assert _wait_refresh(client, inventory_id)["status"] == "success"
    client.delete(f"/api/inventories/{inventory_id}/sources/{source['id']}")
    db = get_sessionmaker()()
    assert db.scalars(select(InventorySourceOutput)).all() == []
    db.close()


def test_a_sources_first_output_with_its_credentials_value_is_scrubbed(client: TestClient) -> None:
    """The worker redacts a credential's value from a source's output; the API keeps that
    output (the first the source ever made) with a warning. This answered 500 once: the warning
    went to an output row that wasn't flushed yet, and the refresh never ended."""
    _login(client)
    inventory_id = _inventory(client)
    credential = client.post(
        "/api/credentials",
        json={"name": "tok", "kind": "env", "env": {"GEN_TOKEN": "gen-token-sentinel-42"}},
    ).json()["id"]
    leaky = (
        "plugin: ansible.builtin.generator\nhosts:\n"
        "  name: \"h-{{ lookup('env', 'GEN_TOKEN') }}-{{ x }}\"\nlayers:\n  x: [a]\n"
    )
    _add_source(client, inventory_id, "leaky", leaky, credential_id=credential)
    refresh = _wait_refresh(client, inventory_id)
    assert refresh["status"] == "success", refresh
    (source,) = client.get(f"/api/inventories/{inventory_id}/sources").json()
    assert (
        source["output_warnings"][0]
        == "a credential's value appeared in the output and was redacted"
    )
    hosts = client.get(f"/api/inventories/{inventory_id}/hosts").json()["hosts"]
    assert hosts and "gen-token-sentinel-42" not in str(hosts)
