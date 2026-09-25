"""CI smoke test: one real run through the API and a worker container.

Usage: python3 smoke_run.py <api base url> <admin password> <path to an OpenSSH private key>
Standard library only (it runs on the CI host, not in the image).
"""

import http.cookiejar
import json
import sys
import time
import urllib.request

PLAYBOOK = """\
- hosts: all
  connection: local
  gather_facts: false
  tasks:
    - name: say hello
      ansible.builtin.debug:
        msg: hello from a worker
"""


def main() -> None:
    base, password, key_path = sys.argv[1:4]
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )

    def call(method: str, path: str, body: dict | None = None) -> dict:
        request = urllib.request.Request(
            f"{base}/api{path}",
            method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Content-Type": "application/json"},
        )
        with opener.open(request, timeout=15) as response:
            return json.loads(response.read() or b"{}")

    call("POST", "/auth/login", {"username": "admin", "password": password})
    playbook = call("POST", "/playbooks", {"name": "smoke.yml", "content": PLAYBOOK})
    inventory = call("POST", "/inventories", {"name": "smoke"})
    call("POST", f"/inventories/{inventory['id']}/hosts", {"hostname": "localhost", "vars": {}})
    with open(key_path) as key:
        credential = call("POST", "/credentials", {"name": "smoke", "private_key": key.read()})
    run = call(
        "POST",
        "/runs",
        {
            "playbook_id": playbook["id"],
            "inventory_id": inventory["id"],
            "credential_id": credential["id"],
        },
    )
    deadline = time.monotonic() + 120
    while run["status"] in ("queued", "running") and time.monotonic() < deadline:
        time.sleep(1)
        run = call("GET", f"/runs/{run['id']}")
    print(json.dumps(run, indent=2))
    if run["status"] != "success" or not run["worker_id"]:
        sys.exit(f"run ended {run['status']!r} ({run.get('status_reason')})")


if __name__ == "__main__":
    main()
