"""The worker's egress filter for real: nftables rules in this network namespace, slot users
refused where the worker (root) gets through. Skipped elsewhere; CI runs it in the backend
image with the worker's compose settings:

    docker run --rm --user 0 --cap-drop ALL --cap-add SETUID --cap-add SETGID --cap-add CHOWN \\
      --cap-add KILL --cap-add NET_ADMIN \\
      --security-opt no-new-privileges:true --read-only --tmpfs /tmp \\
      -e PYTHONDONTWRITEBYTECODE=1 -e ANSIDECK_REQUIRE_ISOLATION=1 -e ANSIDECK_REQUIRE_EGRESS=1 \\
      -e PATH=/app/.venv/bin:/usr/local/bin:/usr/bin:/bin <backend dev image> \\
      python -m pytest --noconftest -p no:cacheprovider tests/test_egress_root.py

The "API" is a listener on 127.0.0.2 (any address the rules name works the same way), so it
doesn't depend on the container's network; 127.0.0.1 stays unblocked for contrast.
"""

import ipaddress
import json
import os
import socket
import subprocess
import sys
import threading

import pytest

from app import run_isolation
from app.run_executor import run_child
from app.run_isolation import identity_for_slot, prepare_homes, wrap
from app.worker import egress

_reasons = [r for r in (run_isolation.check_available(2), egress.check_available()) if r]
if _reasons:
    if os.environ.get("ANSIDECK_REQUIRE_EGRESS") == "1":
        raise RuntimeError(f"the egress filter is required here but unavailable: {_reasons}")
    pytestmark = pytest.mark.skip(reason=f"no egress filter here: {'; '.join(_reasons)}")

from tests.test_isolation_root import _play, _run, _shell  # noqa: E402 - after the skip check

API_ADDRESS = "127.0.0.2"


@pytest.fixture(scope="module", autouse=True)
def _homes() -> None:
    prepare_homes(4)


@pytest.fixture(scope="module")
def port():
    """An echo server on every local address, as root."""
    server = socket.create_server(("0.0.0.0", 0))  # noqa: S104 - loopback only in practice

    def echo(conn: socket.socket) -> None:
        with conn:
            while data := conn.recv(1024):
                conn.sendall(data)

    def serve() -> None:
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            threading.Thread(target=echo, args=(conn,), daemon=True).start()

    threading.Thread(target=serve, daemon=True).start()
    yield server.getsockname()[1]
    server.close()


@pytest.fixture
def egress_filter(port):
    egress_filter = egress.EgressFilter(f"http://{API_ADDRESS}:{port}")
    egress_filter.start()
    yield egress_filter
    _delete_table()


def _delete_table() -> None:
    run_child(
        [egress.nft_path(), "delete", "table", "inet", egress.TABLE],
        timeout=10,
        env={"PATH": "/usr/sbin:/usr/bin"},
    )


def _probe(targets: list[tuple[str, int]], slot: int | None = 0) -> list[str]:
    argument = json.dumps({"name": None, "targets": targets, "timeout": 3})
    command = [sys.executable, "-I", "-S", "-c", egress._PROBE, argument]
    if slot is not None:
        command = wrap(command, identity_for_slot(slot))
    return egress.run_probe(command)["connect"]


def test_a_slot_user_is_refused_where_the_worker_gets_through(egress_filter, port) -> None:
    assert _probe([(API_ADDRESS, port)], slot=None) == ["connected"]
    for slot in (0, 3):
        assert _probe([(API_ADDRESS, port), ("127.0.0.1", port)], slot) == [
            "ECONNREFUSED",
            "connected",  # only the blocked address
        ]


def test_the_metadata_address_is_refused_at_once(egress_filter) -> None:
    assert _probe([("169.254.169.254", 80), ("169.254.170.2", 80)]) == ["ECONNREFUSED"] * 2


def test_udp_to_a_blocked_address_is_refused(egress_filter, port) -> None:
    script = (
        "import socket, sys\n"
        "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        "try:\n"
        f"    s.sendto(b'x', ('{API_ADDRESS}', {port}))\n"
        "    print('sent')\n"
        "except OSError as exc:\n"
        "    print(type(exc).__name__)\n"
    )
    command = wrap([sys.executable, "-I", "-S", "-c", script], identity_for_slot(0))
    result = run_child(command, timeout=10, env={"PATH": "/usr/bin:/bin"})
    assert result.stdout.strip() == "PermissionError", result.stderr


def test_a_playbook_run_is_refused_by_the_api(egress_filter, port) -> None:
    connect = (
        f"python3 -c 'import socket; socket.create_connection((\"{API_ADDRESS}\", {port}), 3)' "
        "2>&1 | tail -1"
    )
    status, stdout = _run(_play(_shell(connect)), slot=1)
    assert status == "successful"
    assert "ConnectionRefusedError" in stdout[0]


def test_the_self_test_passes_and_notices_a_missing_table(egress_filter) -> None:
    slots = [identity_for_slot(0), identity_for_slot(3)]
    assert egress_filter.self_test(slots) is None
    _delete_table()
    reason = egress_filter.self_test(slots)
    assert reason == f"ansideck-run0 could connect to {API_ADDRESS} port {egress_filter.port}"


def test_slot_users_can_neither_read_nor_change_the_rules(egress_filter) -> None:
    nft, env = egress.nft_path(), {"PATH": "/usr/sbin:/usr/bin"}
    attempts = (
        ["list", "ruleset"],
        ["delete", "table", "inet", egress.TABLE],
        ["flush", "ruleset"],
    )
    for args in attempts:
        result = run_child(wrap([nft, *args], identity_for_slot(0)), timeout=10, env=env)
        assert result.returncode != 0
        assert "Operation not permitted" in result.stderr
    listed = run_child([nft, "list", "table", "inet", egress.TABLE], timeout=10, env=env)
    assert API_ADDRESS in listed.stdout


def test_slot_users_have_no_capabilities_although_the_worker_has_net_admin() -> None:
    grep = ["grep", "-E", "^Cap(Inh|Prm|Eff|Amb)", "/proc/self/status"]
    command = wrap(grep, identity_for_slot(0))
    result = run_child(command, timeout=10, env={"PATH": "/usr/bin:/bin"})
    values = {line.split()[0]: line.split()[1] for line in result.stdout.splitlines()}
    assert values == dict.fromkeys(("CapInh:", "CapPrm:", "CapEff:", "CapAmb:"), "0" * 16)


def test_a_new_api_address_is_blocked_and_cuts_an_open_connection(port) -> None:
    """The API moved to 127.0.0.3: a slot connection opened while it was allowed breaks once the
    table follows (the rules don't spare established connections)."""
    addresses = [frozenset({ipaddress.ip_address(API_ADDRESS)})]
    egress_filter = egress.EgressFilter(
        f"http://api.invalid:{port}", resolver=lambda host, p: addresses[-1]
    )
    egress_filter.start()
    script = (
        "import socket, sys\n"
        f"s = socket.create_connection(('127.0.0.3', {port}), 3)\n"
        "print('open', flush=True)\n"
        "sys.stdin.readline()\n"
        "try:\n"
        "    s.sendall(b'ping')\n"
        "    print(s.recv(4) or 'closed')\n"
        "except OSError as exc:\n"
        "    print(type(exc).__name__)\n"
    )
    command = wrap([sys.executable, "-I", "-S", "-c", script], identity_for_slot(0))
    try:
        slot = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            env={"PATH": "/usr/bin:/bin"},
        )
        assert slot.stdout.readline().strip() == "open"
        addresses.append(frozenset({ipaddress.ip_address("127.0.0.3")}))
        assert egress_filter.refresh() is True
        out, _ = slot.communicate("go\n", timeout=15)
        assert out.strip() in ("ConnectionResetError", "BrokenPipeError", "closed"), out
        assert _probe([(API_ADDRESS, port)]) == ["connected"]  # the old address is free again
    finally:
        _delete_table()
