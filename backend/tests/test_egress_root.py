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


# ------------------------------------------------------------------ allowlists (restricted runs)

NET = ipaddress.ip_network


@pytest.fixture
def restricted(egress_filter):
    """Slot 0 limited to 127.0.0.3 (any port) and 127.0.0.4 on one port; released afterwards."""
    yield egress_filter
    for slot in range(4):
        egress_filter.release(identity_for_slot(slot))


def _allow(egress_filter, slot: int, *, hosts=(), ports=()) -> None:
    egress_filter.allow(identity_for_slot(slot), egress.Allowlist(hosts=hosts, ports=ports))


def test_a_restricted_slot_reaches_only_its_hosts_and_extras(restricted, port) -> None:
    other = socket.create_server(("0.0.0.0", 0))  # noqa: S104 - loopback only in practice
    other_port = other.getsockname()[1]
    try:
        _allow(
            restricted,
            0,
            hosts=(NET("127.0.0.3/32"),),
            ports=((NET("127.0.0.4/32"), "tcp", port, port),),
        )
        assert _probe(
            [("127.0.0.3", port), ("127.0.0.3", other_port), ("127.0.0.4", port),
             ("127.0.0.4", other_port), ("127.0.0.1", port)]
        ) == ["connected", "connected", "connected", "ECONNREFUSED", "ECONNREFUSED"]  # fmt: skip
    finally:
        other.close()


def test_the_blocklist_wins_over_a_slots_allowlist(restricted, port) -> None:
    _allow(restricted, 0, hosts=(NET(f"{API_ADDRESS}/32"), NET("127.0.0.3/32")))
    assert _probe([(API_ADDRESS, port), ("127.0.0.3", port)]) == ["ECONNREFUSED", "connected"]


def test_other_slots_are_unaffected_and_keep_their_own_allowlists(restricted, port) -> None:
    _allow(restricted, 0, hosts=(NET("127.0.0.3/32"),))
    _allow(restricted, 2, hosts=(NET("127.0.0.4/32"),))
    targets = [("127.0.0.3", port), ("127.0.0.4", port), ("127.0.0.1", port)]
    assert _probe(targets, slot=0) == ["connected", "ECONNREFUSED", "ECONNREFUSED"]
    assert _probe(targets, slot=2) == ["ECONNREFUSED", "connected", "ECONNREFUSED"]
    assert _probe(targets, slot=1) == ["connected"] * 3  # unrestricted
    assert _probe(targets, slot=None) == ["connected"] * 3  # the worker


def test_udp_and_icmp_outside_the_allowlist_are_refused(restricted, port) -> None:
    _allow(restricted, 0, hosts=(NET("127.0.0.3/32"),))
    script = (
        "import socket\n"
        "for target in ('127.0.0.3', '127.0.0.4'):\n"
        "    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        "    try:\n"
        f"        s.sendto(b'x', (target, {port})); print('sent')\n"
        "    except OSError as exc:\n"
        "        print(type(exc).__name__)\n"
        "try:\n"
        "    p = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)\n"
        "    echo = b'\\x08\\x00\\xf7\\xff\\x00\\x00\\x00\\x00'\n"
        "    p.sendto(echo, ('127.0.0.4', 0)); print('pinged')\n"
        "except OSError as exc:\n"
        "    print(type(exc).__name__)\n"
    )
    command = wrap([sys.executable, "-I", "-S", "-c", script], identity_for_slot(0))
    result = run_child(command, timeout=10, env={"PATH": "/usr/bin:/bin"})
    assert result.stdout.split() == ["sent", "PermissionError", "PermissionError"], result.stderr


def test_refused_destinations_are_recorded_and_survive_a_blocklist_refresh(
    restricted, port
) -> None:
    _allow(restricted, 0, hosts=(NET("127.0.0.3/32"),))
    _probe([("127.0.0.4", port), ("127.0.0.5", 1234)])
    restricted.healthy = False  # forces a reinstall of the blocklist table
    assert restricted.refresh() is True
    refused = restricted.refused(identity_for_slot(0))
    assert {"address": "127.0.0.4", "protocol": "tcp", "port": port} in refused
    assert {"address": "127.0.0.5", "protocol": "tcp", "port": 1234} in refused
    assert restricted.refused(identity_for_slot(1)) == []  # no table


def test_a_released_slot_is_unrestricted_again(restricted, port) -> None:
    _allow(restricted, 0, hosts=(NET("127.0.0.3/32"),))
    assert _probe([("127.0.0.4", port)]) == ["ECONNREFUSED"]
    restricted.release(identity_for_slot(0))
    restricted.release(identity_for_slot(0))  # again: nothing to release, no error
    assert _probe([("127.0.0.4", port)]) == ["connected"]


def test_the_allowlist_self_test_passes(restricted) -> None:
    for slot in (0, 3):
        assert restricted.test_allowlists(identity_for_slot(slot)) is None
    assert restricted.refused(identity_for_slot(0)) == []  # released afterwards


def test_a_restricted_playbook_reaches_its_host_but_not_another(restricted, port) -> None:
    _allow(restricted, 1, hosts=(NET("127.0.0.3/32"),))
    connect = (
        'for h in 127.0.0.3 127.0.0.4; do python3 -c "import socket; '
        f"socket.create_connection(('$h', {port}), 3)\" 2>/dev/null && echo $h ok "
        "|| echo $h refused; done"
    )
    status, stdout = _run(_play(_shell(connect)), slot=1)
    assert status == "successful"
    assert "127.0.0.3 ok" in stdout[0] and "127.0.0.4 refused" in stdout[0]
