"""CI smoke test: dynamic inventory sources refreshed by an isolated worker container.

Usage: python3 smoke_inventory.py <api url> <admin password> <path to an OpenSSH private key>

A static host plus generator and constructed sources; the refresh must succeed, a run must
reach the host through a group only constructed made, and a broken source must fail the
refresh with its reason while runs keep the last good snapshot.
Standard library only (it runs on the CI host, not in the image).
"""

import http.cookiejar
import json
import sys
import time
import urllib.error
import urllib.request

GENERATOR = (
    'plugin: ansible.builtin.generator\nhosts:\n  name: "gen-{{ n }}"\nlayers:\n  n: [a, b]\n'
)
CONSTRUCTED = (
    "plugin: ansible.builtin.constructed\nstrict: false\n"
    "keyed_groups:\n  - key: role\n    prefix: role\n"
)
BROKEN = "plugin: netbox.netbox.nb_inventory\napi_endpoint: http://127.0.0.1:1\n"
PLAYBOOK = """\
- hosts: role_web
  gather_facts: false
  tasks:
    - name: who runs this
      ansible.builtin.command: id -u
      register: uid
      changed_when: false
    - ansible.builtin.assert:
        that: uid.stdout | int >= 20000
"""


def main() -> None:
    base, password, key_path = sys.argv[1:4]
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )

    def call(method: str, path: str, body: dict | None = None):
        request = urllib.request.Request(
            f"{base}/api{path}",
            method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Content-Type": "application/json"},
        )
        try:
            with opener.open(request, timeout=15) as response:
                return json.loads(response.read() or b"null")
        except urllib.error.HTTPError as exc:
            sys.exit(f"{method} {path}: HTTP {exc.code}: {exc.read()[:500]!r}")

    def refreshed(inventory_id: int, after: int) -> dict:
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            latest = call("GET", f"/inventories/{inventory_id}/refreshes?limit=1")
            if (
                latest
                and latest[0]["id"] > after
                and latest[0]["status"]
                not in (
                    "queued",
                    "running",
                )
            ):
                print(json.dumps(latest[0], indent=2))
                return latest[0]
            time.sleep(1)
        sys.exit("no refresh finished in time")

    call("POST", "/auth/login", {"username": "admin", "password": password})
    tag = time.time_ns()
    inventory = call("POST", "/inventories", {"name": f"smoke-dynamic-{tag}"})
    inv = inventory["id"]
    call(
        "POST",
        f"/inventories/{inv}/hosts",
        {"hostname": "localhost", "vars": {"role": "web", "ansible_connection": "local"}},
    )
    call("POST", f"/inventories/{inv}/sources", {"name": "gen", "config": GENERATOR})
    call("POST", f"/inventories/{inv}/sources", {"name": "groups", "config": CONSTRUCTED})
    first = refreshed(inv, 0)
    if first["status"] != "success":
        sys.exit(f"refresh ended {first['status']!r}: {first['error']}")
    targets = call("GET", f"/inventories/{inv}/targets")
    groups = {g["name"]: g["hosts"] for g in targets["groups"]}
    if groups.get("role_web") != 1 or targets["hosts"] != 3:
        sys.exit(f"unexpected snapshot: {targets}")

    with open(key_path) as key:
        credential = call(
            "POST", "/credentials", {"name": f"smoke-dyn-{tag}", "private_key": key.read()}
        )
    playbook = call("POST", "/playbooks", {"name": f"smoke-dyn-{tag}.yml", "content": PLAYBOOK})
    run = call(
        "POST",
        "/runs",
        {
            "playbook_id": playbook["id"],
            "inventory_id": inv,
            "credential_id": credential["id"],
            "group_name": "role_web",
        },
    )
    deadline = time.monotonic() + 120
    while run["status"] in ("queued", "running") and time.monotonic() < deadline:
        time.sleep(1)
        run = call("GET", f"/runs/{run['id']}")
    if run["status"] != "success" or run["hosts_total"] != 1:
        sys.exit(f"run ended {run['status']!r} ({run.get('status_reason')})")

    broken = call("POST", f"/inventories/{inv}/sources", {"name": "nb", "config": BROKEN})
    failed = refreshed(inv, first["id"])
    if failed["status"] != "failed" or f"src{broken['id']}.nb_inventory.yml" not in (
        failed["error"] or ""
    ):
        sys.exit(f"the broken source didn't fail the refresh with its reason: {failed}")
    if call("GET", f"/inventories/{inv}/targets")["snapshot_id"] != targets["snapshot_id"]:
        sys.exit("a failed refresh replaced the snapshot")
    print("dynamic inventory smoke passed")


if __name__ == "__main__":
    main()
