"""CI smoke test: one real run through the API and a worker container.

Usage: python3 smoke_run.py <api url> <admin password> <path to an OpenSSH private key>
       python3 smoke_run.py <api url> <admin password> --store-path <path>
           [--expect-reason <text> | --expect-wait <text>]
       python3 smoke_run.py <api url> <admin password> --ssh-cert <role>:<principal>

With --store-path the credential is a reference into the secret store (created once, then
reused); --expect-reason expects the run to fail with a status reason containing that text, and
--expect-wait expects it to wait in the queue with a reason containing that text (it prints
WAITING then, for the caller to bring the store back) and then to succeed.
With --ssh-cert it is an SSH certificate credential (the store's "ssh" mount): the run's
ssh-agent must hold a certificate, and the run must record its serial.
--check-egress <API host> also has the playbook try the API's ports (as the worker reaches the
API) and cloud metadata: the worker's egress filter must refuse all of them.
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
EGRESS_TASKS = """\
    - name: try the API and cloud metadata
      ansible.builtin.command:
        argv:
          - "{{ ansible_playbook_python }}"
          - -c
          - |
            import errno, socket
            for target in [("API_HOST", 8000), ("API_HOST", 8001), ("API_HOST", 8002),
                           ("169.254.169.254", 80)]:
                try:
                    socket.create_connection(target, 3).close()
                    print(*target, "connected")
                except OSError as exc:
                    print(*target, errno.errorcode.get(exc.errno, exc))
      register: egress
      changed_when: false
    - name: refused, every one
      ansible.builtin.assert:
        that: egress.stdout_lines | select('search', ' ECONNREFUSED$') | list | length == 4
        fail_msg: "{{ egress.stdout_lines }}"
"""
CERTIFICATE_TASKS = """\
    - name: what the run's ssh-agent holds
      ansible.builtin.command: ssh-add -L
      register: agent
      changed_when: false
    - name: a certificate, next to its key
      ansible.builtin.assert:
        that: agent.stdout is search('-cert-v01@openssh[.]com ')
        fail_msg: "{{ agent.stdout_lines | map('split') | map('first') | list }}"
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("base")
    parser.add_argument("password")
    parser.add_argument("key_path", nargs="?")
    parser.add_argument("--store-path")
    parser.add_argument("--expect-reason")
    parser.add_argument("--expect-wait")
    parser.add_argument("--check-egress", metavar="API_HOST")
    parser.add_argument("--ssh-cert", metavar="ROLE:PRINCIPAL")
    args = parser.parse_args()
    if sum(map(bool, (args.key_path, args.store_path, args.ssh_cert))) != 1:
        parser.error("give a private key file, --store-path or --ssh-cert")
    base = args.base
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )

    def call(method: str, path: str, body: dict | None = None) -> dict:
        request = urllib.request.Request(  # noqa: S310 - fixed http URL of the local stack
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
    content = PLAYBOOK
    if args.check_egress:
        content += EGRESS_TASKS.replace("API_HOST", args.check_egress)
    if args.ssh_cert:
        content += CERTIFICATE_TASKS
    playbook = call("POST", "/playbooks", {"name": f"smoke-{tag}.yml", "content": content})
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
    elif args.ssh_cert:
        role, principal = args.ssh_cert.split(":", 1)
        credential = call(
            "POST",
            "/credentials",
            {
                "name": f"smoke-cert-{tag}",
                "kind": "ssh_cert",
                "ssh_mount": "ssh",
                "ssh_role": role,
                "ssh_principals": [principal],
            },
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
    if args.expect_wait:
        deadline = time.monotonic() + 120
        while args.expect_wait not in (run.get("waiting_reason") or ""):
            # (claimed meanwhile, it is "running" until its job gives up on the store)
            if run["status"] not in ("queued", "running") or time.monotonic() > deadline:
                print(json.dumps(run, indent=2))
                sys.exit(f"expected it to wait with {args.expect_wait!r}")
            time.sleep(1)
            run = call("GET", f"/runs/{run['id']}")
        print(f"WAITING: {run['waiting_reason']}", flush=True)
    deadline = time.monotonic() + (240 if args.expect_wait else 120)
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
    if args.ssh_cert and not (run.get("ssh_certificate") or {}).get("serial"):
        sys.exit("the run recorded no SSH certificate")


if __name__ == "__main__":
    main()
