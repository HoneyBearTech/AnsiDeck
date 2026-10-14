"""Refresh before a run with a real worker: it refreshes the sources (ansible-inventory),
then runs the playbook against what the refresh found."""

from tests.test_runs import _create_credential, _create_playbook, _login, _wait_for_completion

# A source ansible-inventory really reads: one host, "gen".
SOURCE = 'plugin: ansible.builtin.generator\nhosts:\n  name: "{{ app }}"\nlayers:\n  app: [gen]\n'
PLAYBOOK = """\
- hosts: all
  connection: local
  gather_facts: false
  tasks:
    - ansible.builtin.debug:
        msg: "hello from {{ inventory_hostname }}"
"""


def test_a_real_worker_refreshes_then_runs_on_what_it_found(client) -> None:
    _login(client)
    inventory_id = client.post("/api/inventories", json={"name": "fresh"}).json()["id"]
    response = client.post(
        f"/api/inventories/{inventory_id}/sources", json={"name": "gen", "config": SOURCE}
    )
    assert response.status_code == 201, response.text
    run = client.post(
        "/api/runs",
        json={
            "playbook_id": _create_playbook(client, PLAYBOOK, name="hello.yml"),
            "inventory_id": inventory_id,
            "credential_id": _create_credential(client),
            "refresh_first": True,
        },
    ).json()
    done = _wait_for_completion(client, run["id"], timeout=60)
    assert done["status"] == "success", (done["status_reason"], done["return_code"])
    assert done["refresh_first"] is True and done["inventory_snapshot_hosts"] == 1
    log = client.get(f"/api/runs/{run['id']}/log").text
    assert "hello from gen" in log
