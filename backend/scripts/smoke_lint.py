"""CI smoke test: playbook checks (ansible-lint) run by an isolated worker container.

Usage: python3 smoke_lint.py <api url> <admin password>

Unsaved text with known problems must come back with those rules and lines, broken YAML as an
error finding, and a saved playbook checked by id; each result names the ansible-lint version.
Standard library only (it runs on the CI host, not in the image).
"""

import http.cookiejar
import json
import sys
import time
import urllib.error
import urllib.request

UNTIDY = "- hosts: all\n  tasks:\n    - shell: echo hi\n"
BROKEN = "- hosts: all\n  tasks:\n   - name: x\n     debug: [\n"


def main() -> None:
    base, password = sys.argv[1:3]
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )

    def call(method: str, path: str, body: dict | None = None):
        request = urllib.request.Request(  # noqa: S310 - fixed http URL of the local stack
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

    def checked(lint: dict) -> dict:
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            result = call("GET", f"/lint-jobs/{lint['id']}")
            if result["status"] not in ("queued", "running"):
                print(json.dumps({k: v for k, v in result.items() if k != "findings"}, indent=2))
                if result["status"] != "success" or not result["ansible_lint_version"]:
                    sys.exit(f"check {lint['id']} did not succeed: {result['error']}")
                return result
            time.sleep(1)
        sys.exit("no check finished in time")

    def found(result: dict) -> dict[str, dict]:
        return {f["rule"]: f for f in result["findings"]}

    call("POST", "/auth/login", {"username": "admin", "password": password})
    untidy = found(checked(call("POST", "/playbooks/lint", {"content": UNTIDY})))
    for rule in ("name[play]", "fqcn[action-core]", "no-changed-when"):
        if rule not in untidy:
            sys.exit(f"expected {rule} in {sorted(untidy)}")
    if (untidy["fqcn[action-core]"]["line"], untidy["fqcn[action-core]"]["column"]) != (3, 7):
        sys.exit(f"wrong position: {untidy['fqcn[action-core]']}")

    broken = found(checked(call("POST", "/playbooks/lint", {"content": BROKEN})))
    if broken.get("load-failure[yaml]", {}).get("level") != "error":
        sys.exit(f"broken YAML not reported as an error: {broken}")

    playbook = call(
        "POST", "/playbooks", {"name": f"smoke-lint-{time.time_ns()}.yml", "content": UNTIDY}
    )
    saved = checked(call("POST", f"/playbooks/{playbook['id']}/lint"))
    if "fqcn[action-core]" not in found(saved):
        sys.exit("the saved playbook's check found nothing")
    call("DELETE", f"/playbooks/{playbook['id']}")
    print("playbook checks: ok")


if __name__ == "__main__":
    main()
