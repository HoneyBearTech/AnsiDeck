"""CI smoke test: one real run through the API and a worker container.

Usage: python3 smoke_run.py <api url> <admin password> <path to an OpenSSH private key>
       python3 smoke_run.py <api url> <admin password> --store-path <path> [--expect-reason <text>]

With --store-path the credential is a reference into the secret store (created once, then
reused); --expect-reason expects the run to fail with a status reason containing that text.
Standard library only (it runs on the CI host, not in the image).
"""

import argparse
import http.cookiejar
import json
import sys
import time
import urllib.error
import urllib.request

# The worker must be isolated: the run executes as its slot's own user (uid 20000 + slot),
# and a module task (unlike debug) needs that user's home for ansible's temp files.
PLAYBOOK = """\
- hosts: all
  connection: local
  gather_facts: false
  tasks:
    - name: say hello
      ansible.builtin.debug:
        msg: hello from a worker
    - name: who runs this
      ansible.builtin.command: id -u
      register: uid
      changed_when: false
    - name: a slot user, not the worker's own
      ansible.builtin.assert:
        that: uid.stdout | int >= 20000
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("base")
    parser.add_argument("password")
    parser.add_argument("key_path", nargs="?")
    parser.add_argument("--store-path")
    parser.add_argument("--expect-reason")
    args = parser.parse_args()
    if bool(args.key_path) == bool(args.store_path):
        parser.error("give a private key file or --store-path")
    base = args.base
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
        try:
            with opener.open(request, timeout=15) as response:
                return json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as exc:
            sys.exit(f"{method} {path}: HTTP {exc.code}: {exc.read()[:500]!r}")

    call("POST", "/auth/login", {"username": "admin", "password": args.password})
    tag = time.time_ns()  # names are unique, and this script runs more than once
    playbook = call("POST", "/playbooks", {"name": f"smoke-{tag}.yml", "content": PLAYBOOK})
    inventory = call("POST", "/inventories", {"name": f"smoke-{tag}"})
    call("POST", f"/inventories/{inventory['id']}/hosts", {"hostname": "localhost", "vars": {}})
    if args.store_path:
        existing = [c for c in call("GET", "/credentials") if c["name"] == "smoke-store"]
        credential = (
            existing[0]
            if existing
            else call(
                "POST", "/credentials", {"name": "smoke-store", "store_path": args.store_path}
            )
        )
        print(f"credential {credential['id']}: {credential['store_location']}")
    else:
        with open(args.key_path) as key:
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
    if args.expect_reason:
        if run["status"] != "failed" or args.expect_reason not in (run.get("status_reason") or ""):
            sys.exit(f"expected a failure with {args.expect_reason!r}, got {run['status']!r}")
        return
    if run["status"] != "success" or not run["worker_id"]:
        sys.exit(f"run ended {run['status']!r} ({run.get('status_reason')})")


if __name__ == "__main__":
    main()
