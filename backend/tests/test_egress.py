"""The worker's egress filter (app.worker.egress), the parts that run anywhere. The real thing,
as root with NET_ADMIN in the worker image, is tests/test_egress_root.py."""

import ipaddress
import json
import logging
import socket
import subprocess
import sys
import threading

import pytest
from pydantic import ValidationError

from app import run_executor
from app.run_isolation import identity_for_slot
from app.worker import __main__ as worker_main
from app.worker import egress
from app.worker.egress import EgressError, EgressFilter
from app.worker.settings import WorkerSettings

API = "http://backend:8001"
NET = ipaddress.ip_network


def _settings(**values) -> WorkerSettings:
    return WorkerSettings(worker_token="t" * 40, **values)


# ------------------------------------------------------------------ the table


def test_the_table_rejects_slot_users_traffic_to_the_blocked_networks() -> None:
    v4, v6 = (
        "meta skuid 20000-20063 ip daddr @blocked4",
        "meta skuid 20000-20063 ip6 daddr @blocked6",
    )
    tcp, other = "counter reject with tcp reset", "counter reject with icmpx admin-prohibited"
    interval = "flags interval; elements ="
    assert egress.ruleset([NET("169.254.0.0/16"), NET("10.0.0.5/32"), NET("fe80::/10")]) == (
        "add table inet ansideck_egress\n"
        "delete table inet ansideck_egress\n"
        "table inet ansideck_egress {\n"
        f"  set blocked4 {{ type ipv4_addr; {interval} {{ 10.0.0.5/32, 169.254.0.0/16 }}; }}\n"
        f"  set blocked6 {{ type ipv6_addr; {interval} {{ fe80::/10 }}; }}\n"
        "  chain output {\n"
        "    type filter hook output priority filter; policy accept;\n"
        f"    {v4} meta l4proto tcp {tcp}\n"
        f"    {v4} {other}\n"
        f"    {v6} meta l4proto tcp {tcp}\n"
        f"    {v6} {other}\n"
        "  }\n"
        "}\n"
    )


def test_the_table_merges_overlaps_and_treats_mapped_addresses_as_ipv4() -> None:
    text = egress.ruleset(
        [NET("10.0.0.0/8"), NET("10.1.2.3/32"), NET("::ffff:192.0.2.0/120"), NET("10.0.0.0/9")]
    )
    assert "elements = { 10.0.0.0/8, 192.0.2.0/24 };" in text
    assert "set blocked6 { type ipv6_addr; flags interval; }" in text  # empty: no elements


def test_without_ipv6_the_table_is_ipv4_only() -> None:
    text = egress.ruleset([NET("169.254.0.0/16"), NET("fe80::/10")], ipv6=False)
    assert text.startswith("add table ip ansideck_egress\ndelete table ip ansideck_egress\n")
    assert "ip6" not in text and "blocked6" not in text
    assert "reject with icmp admin-prohibited" in text


def test_the_table_covers_every_slot_user_of_the_image() -> None:
    assert (egress.FIRST_UID, egress.LAST_UID) == (20000, 20063)


# ------------------------------------------------------------------ parsing


def test_blocked_networks_are_parsed_from_a_comma_separated_list() -> None:
    assert egress.parse_networks(" 10.244.0.0/16, 192.0.2.7 ,,fd00::/8, ::ffff:198.51.100.1") == [
        NET("10.244.0.0/16"),
        NET("192.0.2.7/32"),
        NET("fd00::/8"),
        NET("198.51.100.1/32"),
    ]
    assert egress.parse_networks("") == []
    assert egress.parse_networks("10.1.2.3/8") == [NET("10.0.0.0/8")]  # host bits allowed


@pytest.mark.parametrize("text", ["backend", "10.0.0.0/33", "10.0.0.1-10.0.0.9"])
def test_a_blocked_network_must_be_an_address_or_cidr(text) -> None:
    with pytest.raises(ValueError, match="is not an IP address or network"):
        egress.parse_networks(text)


def test_blocking_dockers_dns_server_is_refused() -> None:
    with pytest.raises(ValueError, match="would block DNS for runs"):
        egress.parse_networks("127.0.0.0/8")


@pytest.mark.parametrize(
    ("url", "endpoint"),
    [
        ("http://backend:8001", ("backend", 8001)),
        ("http://backend", ("backend", 80)),
        ("https://api.example.com/", ("api.example.com", 443)),
        ("http://[fd00::5]:8001", ("fd00::5", 8001)),
    ],
)
def test_the_api_endpoint_comes_from_ansideck_api_url(url, endpoint) -> None:
    assert egress.api_endpoint(url) == endpoint


@pytest.mark.parametrize("url", ["backend:8001", "ftp://backend", "http://"])
def test_the_api_url_must_name_a_host(url) -> None:
    with pytest.raises(ValueError, match="must be an http"):
        egress.api_endpoint(url)


def test_resolving_returns_every_address_without_zones(monkeypatch) -> None:
    infos = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("172.20.0.2", 8001)),
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("fe80::1%eth0", 8001, 0, 2)),
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::ffff:172.20.0.2", 8001, 0, 0)),
    ]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: infos)
    assert egress.resolve("backend", 8001) == {
        ipaddress.ip_address("172.20.0.2"),
        ipaddress.ip_address("fe80::1"),
    }


def test_an_address_needs_no_lookup(monkeypatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: pytest.fail("looked up"))
    assert egress.resolve("::ffff:10.0.0.1", 80) == {ipaddress.ip_address("10.0.0.1")}


# ------------------------------------------------------------------ check_available


def _linux_root(monkeypatch, nft="/usr/sbin/nft") -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(egress.os, "geteuid", lambda: 0)
    monkeypatch.setattr(egress, "nft_path", lambda: nft)


def _status(tmp_path, caps: int) -> str:
    path = tmp_path / "status"
    path.write_text(f"Name:\tpython\nCapEff:\t{caps:016x}\n")
    return str(path)


def test_the_filter_needs_net_admin_and_nft(monkeypatch, tmp_path) -> None:
    _linux_root(monkeypatch)
    assert egress.check_available(_status(tmp_path, 1 << 12)) is None
    assert "lacks the NET_ADMIN capability" in egress.check_available(_status(tmp_path, 0xFF))
    _linux_root(monkeypatch, nft=None)
    assert egress.check_available(_status(tmp_path, 1 << 12)) == "nft (nftables) is not installed"


def test_the_filter_needs_root_on_linux(monkeypatch, tmp_path) -> None:
    _linux_root(monkeypatch)
    monkeypatch.setattr(egress.os, "geteuid", lambda: 1000)
    assert "not running as root" in egress.check_available(_status(tmp_path, 1 << 12))
    monkeypatch.setattr(sys, "platform", "darwin")
    assert egress.check_available() == "the egress filter needs Linux"


def test_nft_is_found_outside_the_path(monkeypatch) -> None:
    monkeypatch.setattr(egress.shutil, "which", lambda name: None)
    monkeypatch.setattr(egress.os.path, "exists", lambda path: path == "/usr/sbin/nft")
    assert egress.nft_path() == "/usr/sbin/nft"


# ------------------------------------------------------------------ running nft


def _fake_nft(tmp_path, monkeypatch, script: str) -> None:
    nft = tmp_path / "nft"
    nft.write_text(f"#!/bin/sh\n{script}\n")
    nft.chmod(0o755)
    monkeypatch.setattr(egress, "nft_path", lambda: str(nft))


def test_nft_gets_the_script_on_stdin(tmp_path, monkeypatch) -> None:
    _fake_nft(tmp_path, monkeypatch, f'[ "$1 $2" = "-f -" ] && cat > {tmp_path}/got')
    egress.apply("table inet x {}\n")
    assert (tmp_path / "got").read_text() == "table inet x {}\n"


def test_an_nft_error_says_what_nft_said(tmp_path, monkeypatch) -> None:
    failing = 'cat > /dev/null; echo "Error: Could not process rule" >&2; exit 1'
    _fake_nft(tmp_path, monkeypatch, failing)
    with pytest.raises(EgressError, match="Could not process rule"):
        egress.apply("x")


def test_without_ipv6_the_ipv4_table_is_installed(monkeypatch) -> None:
    applied = []

    def apply(script: str) -> None:
        applied.append(script.split("\n")[0])
        if "inet" in script:
            raise EgressError("inet unsupported")

    monkeypatch.setattr(egress, "apply", apply)
    monkeypatch.setattr(egress.os.path, "exists", lambda path: False)  # no /proc/net/if_inet6
    egress.install([NET("169.254.0.0/16")])
    assert applied == ["add table inet ansideck_egress", "add table ip ansideck_egress"]


def test_with_ipv6_an_nft_error_is_not_hidden(monkeypatch) -> None:
    monkeypatch.setattr(egress, "apply", lambda script: (_ for _ in ()).throw(EgressError("no")))
    monkeypatch.setattr(egress.os.path, "exists", lambda path: True)
    with pytest.raises(EgressError, match="no"):
        egress.install([])


def test_run_child_returns_the_output_and_stops_a_command_that_hangs() -> None:
    env = {"PATH": "/usr/bin:/bin"}
    done = run_executor.run_child(
        [sys.executable, "-c", "print(input())"], input_text="hi\n", timeout=30, env=env
    )
    assert (done.returncode, done.stdout) == (0, "hi\n")
    with pytest.raises(subprocess.TimeoutExpired):
        run_executor.run_child(
            [sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.5, env=env
        )
    with run_executor.CHILDREN_LOCK:
        assert not run_executor._children  # collected, not left to the reaper


# ------------------------------------------------------------------ following the API's address


class FakeNet:
    def __init__(self, *addresses: str) -> None:
        self.addresses = {ipaddress.ip_address(a) for a in addresses}
        self.installed: list[list] = []
        self.applied: list[str] = []
        self.fail_install = False
        self.fail_lookup = False

    def resolve(self, host: str, port: int) -> frozenset:
        assert (host, port) == ("backend", 8001)
        if self.fail_lookup:
            raise socket.gaierror("Name or service not known")
        return frozenset(self.addresses)

    def install(self, networks: list) -> None:
        if self.fail_install:
            raise EgressError("nft broke")
        self.installed.append(networks)

    def apply(self, script: str) -> None:
        if self.fail_install:
            raise EgressError("nft broke")
        self.applied.append(script)


def _filter(net: FakeNet, **kwargs) -> EgressFilter:
    return EgressFilter(
        API, resolver=net.resolve, installer=net.install, applier=net.apply, **kwargs
    )


def test_the_table_holds_metadata_link_local_extras_and_the_api() -> None:
    net = FakeNet("172.20.0.2")
    egress_filter = _filter(net, extra=[NET("10.244.0.0/16")])
    egress_filter.start()
    assert egress_filter.healthy
    (networks,) = net.installed
    assert NET("169.254.0.0/16") in networks and NET("fd00:ec2::254/128") in networks
    assert NET("100.100.100.200/32") in networks
    assert NET("fe80::/10") in networks and NET("10.244.0.0/16") in networks
    assert NET("172.20.0.2/32") in networks
    assert egress_filter.describe() == "egress filtered (API 172.20.0.2)"


def test_cloud_metadata_can_be_allowed_but_link_local_stays_blocked() -> None:
    net = FakeNet("172.20.0.2")
    _filter(net, block_metadata=False).start()
    (networks,) = net.installed
    assert not set(egress.METADATA_NETWORKS) & set(networks)
    assert NET("fe80::/10") in networks


def test_an_api_that_doesnt_resolve_yet_still_gets_the_static_table() -> None:
    net = FakeNet()
    net.fail_lookup = True
    egress_filter = _filter(net)
    egress_filter.start()
    assert egress_filter.addresses == frozenset() and net.installed


def test_the_table_follows_the_api_to_a_new_address(caplog) -> None:
    caplog.set_level(logging.INFO, logger="app.worker.egress")
    net = FakeNet("172.20.0.2")
    egress_filter = _filter(net)
    egress_filter.start()
    assert egress_filter.refresh() is False  # unchanged: not installed again
    net.addresses = {ipaddress.ip_address("172.20.0.5")}
    assert egress_filter.refresh() is True
    assert NET("172.20.0.5/32") in net.installed[-1]
    assert NET("172.20.0.2/32") not in net.installed[-1]
    assert "the API's address changed (172.20.0.2 -> 172.20.0.5)" in caplog.text


def test_while_the_api_doesnt_resolve_the_old_address_stays_blocked() -> None:
    net = FakeNet("172.20.0.2")
    egress_filter = _filter(net)
    egress_filter.start()
    net.fail_lookup = True
    assert egress_filter.refresh() is False
    assert egress_filter.addresses == {ipaddress.ip_address("172.20.0.2")}


def test_a_failed_update_is_retried_and_marks_the_filter_unhealthy() -> None:
    net = FakeNet("172.20.0.2")
    egress_filter = _filter(net)
    egress_filter.start()
    net.addresses = {ipaddress.ip_address("172.20.0.5")}
    net.fail_install = True
    with pytest.raises(EgressError):
        egress_filter.refresh()
    assert not egress_filter.healthy
    net.fail_install = False
    assert egress_filter.refresh() is True  # same addresses, but the last update failed
    assert egress_filter.healthy


def test_watching_logs_a_failed_update_and_carries_on(monkeypatch, caplog) -> None:
    net = FakeNet("172.20.0.2")
    egress_filter = _filter(net)
    egress_filter.start()
    net.addresses = {ipaddress.ip_address("172.20.0.5")}
    net.fail_install = True
    monkeypatch.setattr(egress, "REFRESH_SECONDS", 0.01)
    stop = threading.Event()
    watcher = threading.Thread(target=egress_filter.watch, args=(stop,))
    watcher.start()
    while "could not update the egress filter: nft broke" not in caplog.text:
        stop.wait(0.01)
    stop.set()
    watcher.join(5)
    assert not watcher.is_alive()


# ------------------------------------------------------------------ the self-test


class FakeProber:
    """Answers the probe: as the worker (uid 0) or a slot user (a setpriv-wrapped command)."""

    def __init__(self, worker="connected", slot="ECONNREFUSED", metadata="ECONNREFUSED", dns="ok"):
        self.worker, self.slot, self.metadata, self.dns = worker, slot, metadata, dns
        self.calls: list[tuple[str, list]] = []

    def __call__(self, command: list[str]) -> dict:
        args = json.loads(command[-1])
        who = "slot" if command[0].endswith("setpriv") else "worker"
        self.calls.append((who, args["targets"]))
        results = []
        for host, _port in args["targets"]:
            if host == "169.254.169.254":
                results.append(self.metadata)
            else:
                results.append(self.slot if who == "slot" else self.worker)
        return {"resolved": self.dns if args["name"] else None, "connect": results}


def _tested(prober: FakeProber, *addresses: str, **kwargs) -> EgressFilter:
    net = FakeNet(*addresses or ("172.20.0.2",))
    egress_filter = EgressFilter(
        API, resolver=net.resolve, installer=net.install, applier=net.apply, prober=prober,
        **kwargs,
    )  # fmt: skip
    egress_filter.start()
    return egress_filter


SLOTS = [identity_for_slot(0), identity_for_slot(3)]


def test_the_self_test_passes_when_slot_users_are_refused_where_the_worker_gets_through() -> None:
    prober = FakeProber()
    assert _tested(prober).self_test(SLOTS) is None
    slot_probes = [targets for who, targets in prober.calls if who == "slot"]
    assert slot_probes == [[["172.20.0.2", 8001], ["169.254.169.254", 80]]] * 2
    worker_probes = [targets for who, targets in prober.calls if who == "worker"]
    assert worker_probes == [[["172.20.0.2", 8001]]] * 4  # before and after each slot's


def test_the_self_test_fails_if_a_slot_user_gets_through() -> None:
    reason = _tested(FakeProber(slot="connected")).self_test(SLOTS)
    assert reason == "ansideck-run0 could connect to 172.20.0.2 port 8001"


def test_the_self_test_fails_if_the_metadata_address_isnt_refused() -> None:
    reason = _tested(FakeProber(metadata="timeout")).self_test(SLOTS)
    assert reason == "ansideck-run0 wasn't refused by the metadata address (timeout)"


def test_the_metadata_address_isnt_probed_when_it_is_allowed() -> None:
    prober = FakeProber(metadata="connected")
    assert _tested(prober, block_metadata=False).self_test(SLOTS) is None
    assert all(["169.254.169.254", 80] not in targets for _, targets in prober.calls)


def test_the_self_test_fails_if_runs_can_no_longer_look_up_names() -> None:
    reason = _tested(FakeProber(dns="[Errno -3] Temporary failure in name resolution")).self_test(
        SLOTS
    )
    assert (
        reason
        == "ansideck-run0 can't look up names: [Errno -3] Temporary failure in name resolution"
    )


def test_the_self_test_retries_when_the_worker_cant_reach_the_api_either(monkeypatch) -> None:
    monkeypatch.setattr(egress.time, "sleep", lambda seconds: None)
    prober = FakeProber(worker="ECONNREFUSED")
    reason = _tested(prober).self_test(SLOTS[:1])
    assert reason.startswith("couldn't check the filter: the worker got ECONNREFUSED")
    assert len([c for c in prober.calls if c[0] == "slot"]) == egress._PROBE_ATTEMPTS


def test_one_reachable_api_address_proves_the_filter() -> None:
    """An address the worker can't use (e.g. IPv6 without a route) doesn't matter, as long as no
    slot gets through anywhere."""

    class Mixed(FakeProber):
        def __call__(self, command):
            answer = super().__call__(command)
            if not command[0].endswith("setpriv"):
                answer["connect"][1] = "ENETUNREACH"
            return answer

    assert _tested(Mixed(), "172.20.0.2", "fd00::2").self_test(SLOTS) is None


def test_the_self_test_needs_the_apis_address() -> None:
    net = FakeNet()
    net.fail_lookup = True
    egress_filter = EgressFilter(
        API, resolver=net.resolve, installer=net.install, applier=net.apply, prober=FakeProber()
    )
    egress_filter.start()
    assert egress_filter.self_test(SLOTS) == "the API's address (backend) doesn't resolve"


def test_the_probe_reports_connected_refused_and_name_lookups() -> None:
    """The probe program itself, as the current user, against a port that listens and one
    that doesn't."""
    listening = socket.create_server(("127.0.0.1", 0))
    closed = socket.create_server(("127.0.0.1", 0))
    closed_port = closed.getsockname()[1]
    closed.close()
    try:
        argument = json.dumps(
            {
                "name": "localhost",
                "targets": [["127.0.0.1", listening.getsockname()[1]], ["127.0.0.1", closed_port]],
                "timeout": 3,
            }
        )
        out = egress.run_probe([sys.executable, "-I", "-S", "-c", egress._PROBE, argument])
    finally:
        listening.close()
    assert out == {"resolved": "ok", "connect": ["connected", "ECONNREFUSED"]}


# ------------------------------------------------------------------ settings and startup


def test_the_filter_is_on_and_metadata_blocked_by_default() -> None:
    settings = _settings()
    assert settings.worker_egress_filter is True
    assert settings.worker_allow_cloud_metadata is False
    assert settings.blocked_networks == []


def test_the_filter_settings_come_from_the_environment(monkeypatch) -> None:
    monkeypatch.setenv("WORKER_EGRESS_FILTER", "false")
    monkeypatch.setenv("WORKER_ALLOW_CLOUD_METADATA", "true")
    monkeypatch.setenv("WORKER_BLOCKED_NETWORKS", "10.244.0.0/16")
    settings = _settings()
    assert (settings.worker_egress_filter, settings.worker_allow_cloud_metadata) == (False, True)
    assert settings.blocked_networks == [NET("10.244.0.0/16")]


def test_a_bad_blocked_network_is_an_invalid_setting() -> None:
    with pytest.raises(ValidationError, match="'nope' is not an IP address or network"):
        _settings(worker_blocked_networks="10.0.0.0/8, nope")


def _available(monkeypatch, reason=None, start_error=None) -> list:
    started = []

    def start(self) -> None:
        if start_error:
            raise EgressError(start_error)
        started.append(self)

    monkeypatch.setattr(egress, "check_available", lambda: reason)
    monkeypatch.setattr(EgressFilter, "start", start)
    return started


def test_a_worker_that_can_filter_installs_the_filter(monkeypatch) -> None:
    started = _available(monkeypatch)
    settings = _settings(
        environment="production",
        worker_allow_cloud_metadata=True,
        worker_blocked_networks="10.9.0.0/16",
    )
    egress_filter = worker_main.check_egress(settings, isolated=True)
    assert started == [egress_filter]
    assert egress_filter.block_metadata is False
    assert NET("10.9.0.0/16") in egress_filter.static


def test_a_production_worker_that_cannot_filter_refuses_to_start(monkeypatch) -> None:
    _available(monkeypatch, reason="the worker lacks the NET_ADMIN capability (compose: cap_add)")
    with pytest.raises(
        SystemExit,
        match=r"runs could reach the API and cloud metadata \(the worker lacks the NET_ADMIN",
    ):
        worker_main.check_egress(_settings(environment="production"), isolated=True)


def test_a_production_worker_whose_nft_fails_refuses_to_start(monkeypatch) -> None:
    _available(monkeypatch, start_error="Error: Could not process rule: No such file or directory")
    with pytest.raises(SystemExit, match=r"\(nft failed: Error: Could not process rule"):
        worker_main.check_egress(_settings(environment="production"), isolated=True)


def test_a_development_worker_that_cannot_filter_warns(monkeypatch, caplog) -> None:
    _available(monkeypatch, reason="the egress filter needs Linux")
    assert worker_main.check_egress(_settings(), isolated=True) is None
    assert "cloud metadata (the egress filter needs Linux)" in caplog.text


def test_the_filter_can_be_turned_off_even_in_production(monkeypatch, caplog) -> None:
    started = _available(monkeypatch)
    settings = _settings(environment="production", worker_egress_filter=False)
    assert worker_main.check_egress(settings, isolated=True) is None
    assert not started
    assert "the egress filter is off (WORKER_EGRESS_FILTER=false)" in caplog.text


def test_without_isolation_there_is_no_filter(monkeypatch, caplog) -> None:
    started = _available(monkeypatch)
    assert worker_main.check_egress(_settings(), isolated=False) is None
    assert not started
    assert "runs are not isolated, so they can reach the API" in caplog.text


def test_verifying_tests_the_first_and_last_slot(monkeypatch) -> None:
    egress_filter = _tested(FakeProber())
    tested = []
    monkeypatch.setattr(egress_filter, "self_test", tested.extend)
    settings = _settings(environment="production", worker_slots=4)
    assert worker_main.verify_egress(settings, egress_filter) is egress_filter
    assert [identity.uid for identity in tested] == [20000, 20003]
    assert worker_main.verify_egress(settings, None) is None


def test_a_production_worker_whose_self_test_fails_refuses_to_start() -> None:
    egress_filter = _tested(FakeProber(slot="connected"))
    with pytest.raises(SystemExit, match=r"ansideck-run0 could connect to 172\.20\.0\.2 port 8001"):
        worker_main.verify_egress(_settings(environment="production"), egress_filter)


def test_a_development_worker_whose_self_test_fails_warns(caplog) -> None:
    egress_filter = _tested(FakeProber(slot="connected"))
    assert worker_main.verify_egress(_settings(), egress_filter) is None
    assert "ansideck-run0 could connect" in caplog.text


# ------------------------------------------------------------------ allowlists (restricted runs)


def _allowlist(**kwargs) -> egress.Allowlist:
    return egress.Allowlist(**kwargs)


def test_a_slot_table_allows_dns_its_hosts_and_extras_and_refuses_the_rest() -> None:
    allowlist = _allowlist(
        hosts=(NET("192.0.2.10/32"), NET("2001:db8::10/128")),
        ports=((NET("198.51.100.0/24"), "tcp", 443, 443),),
    )
    script = egress.slot_ruleset(3, 20003, allowlist, [ipaddress.ip_address("192.168.65.7")])
    assert script.startswith(
        "add table inet ansideck_egress_slot3\ndelete table inet ansideck_egress_slot3\n"
    )
    assert "elements = { 192.0.2.10/32 }" in script and "elements = { 2001:db8::10/128 }" in script
    assert "198.51.100.0-198.51.100.255 . tcp . 443" in script
    assert "elements = { 192.168.65.7 }" in script
    # Docker's resolver by its original port (its nat rule changes it before this hook).
    assert "ip daddr 127.0.0.11 meta l4proto { tcp, udp } ct original proto-dst 53 accept" in script
    lines = script.splitlines()
    rejects = [i for i, line in enumerate(lines) if "reject" in line]
    accepts = [i for i, line in enumerate(lines) if line.endswith("accept")]
    assert rejects and max(accepts) < min(rejects)
    # Everything else is refused, any protocol (ICMP too), and recorded.
    assert lines[rejects[-1]].strip() == "counter reject with icmpx admin-prohibited"
    assert "add @refused4 { ip daddr . meta l4proto . th dport }" in script


def test_slot_tables_match_only_the_slots_own_uid_positively() -> None:
    """With `meta skuid != uid accept` the resets of the rejects (which have no socket) would be
    rejected too, and refused connections would hang."""
    script = egress.slot_ruleset(0, 20000, _allowlist(), [])
    assert "    meta skuid 20000 jump restrict" in script
    assert "!=" not in script


def test_overlapping_extras_become_disjoint_elements() -> None:
    ports = (
        (NET("10.0.0.0/8"), "tcp", 443, 443),
        (NET("10.1.0.0/16"), "tcp", 400, 500),
        (NET("10.2.0.0/16"), "tcp", 8000, 8100),
        (NET("10.2.0.0/16"), "tcp", 8050, 8200),
    )
    elements = egress._disjoint([], list(ports), 4)
    spans = [(ipaddress.ip_address(lo), ipaddress.ip_address(hi), p) for (lo, hi), _, p in elements]
    assert spans == [
        (ipaddress.ip_address("10.0.0.0"), ipaddress.ip_address("10.0.255.255"), (443, 443)),
        (ipaddress.ip_address("10.1.0.0"), ipaddress.ip_address("10.1.255.255"), (400, 500)),
        (ipaddress.ip_address("10.2.0.0"), ipaddress.ip_address("10.2.255.255"), (443, 443)),
        (ipaddress.ip_address("10.2.0.0"), ipaddress.ip_address("10.2.255.255"), (8000, 8200)),
        (ipaddress.ip_address("10.3.0.0"), ipaddress.ip_address("10.255.255.255"), (443, 443)),
    ]
    # No two elements of a protocol overlap in both address and port.
    for i, (a, proto_a, pa) in enumerate(elements):
        for b, proto_b, pb in elements[i + 1 :]:
            assert not (
                proto_a == proto_b
                and a[0] <= b[1]
                and b[0] <= a[1]
                and pa[0] <= pb[1]
                and pb[0] <= pa[1]
            )


def test_extras_inside_a_hosts_network_are_dropped() -> None:
    elements = egress._disjoint(
        [NET("10.9.0.0/24")],
        [(NET("10.9.0.5/32"), "udp", 53, 53), (NET("10.8.0.1/32"), "udp", 53, 53)],
        4,
    )
    assert [(ipaddress.ip_address(lo), p) for (lo, _), _, p in elements] == [
        (ipaddress.ip_address("10.8.0.1"), (53, 53))
    ]


def test_without_ipv6_slot_tables_are_ipv4_only() -> None:
    script = egress.slot_ruleset(1, 20001, _allowlist(hosts=(NET("192.0.2.1/32"),)), [], ipv6=False)
    assert script.startswith("add table ip ansideck_egress_slot1")
    assert "ip6" not in script and "ipv6_addr" not in script
    assert "reject with icmp admin-prohibited" in script


def _resolver(table: dict):
    def resolve(name: str, port: int) -> frozenset:
        try:
            return frozenset({ipaddress.ip_address(name)})
        except ValueError:
            pass
        found = table.get(name)
        if isinstance(found, str):
            raise socket.gaierror(-2, found)
        return frozenset(ipaddress.ip_address(a) for a in found)

    return resolve


def test_resolving_an_allowlist_finds_every_address_of_every_name() -> None:
    spec = {
        "hosts": [
            {"host": "web1", "address": "web1.lan", "required": True},
            {"host": "db", "address": "192.0.2.7", "required": True},
            {"host": "inner", "address": "inner.corp", "required": False},
        ],
        "jump_hosts": [{"host": "bastion", "address": "bastion.lan", "port": 2222}],
        "extras": [
            {"target": "203.0.113.0/24", "ports": None},
            {"target": "mirror.lan", "ports": [[80, 80], [443, 443]]},
        ],
        "warnings": ["w"],
    }
    resolve = _resolver({
        "web1.lan": ["192.0.2.1", "2001:db8::1"], "bastion.lan": ["192.0.2.9"],
        "mirror.lan": ["198.51.100.4"], "inner.corp": "Name or service not known",
    })  # fmt: skip
    allowlist = egress.resolve_allowlist(spec, resolver=resolve)
    assert set(allowlist.hosts) == {
        NET("192.0.2.1/32"),
        NET("2001:db8::1/128"),
        NET("192.0.2.7/32"),
        NET("203.0.113.0/24"),
    }
    assert set(allowlist.ports) == {
        (NET("192.0.2.9/32"), "tcp", 2222, 2222),
        *((NET("198.51.100.4/32"), proto, p, p) for proto in ("tcp", "udp") for p in (80, 443)),
    }
    report = allowlist.report
    assert report["hosts"][0] == {
        "host": "web1",
        "address": "web1.lan",
        "addresses": ["192.0.2.1", "2001:db8::1"],
    }
    assert report["unresolved"] == [
        {"host": "inner", "address": "inner.corp", "reason": "Name or service not known"}
    ]
    assert report["jump_hosts"][0]["port"] == 2222 and report["warnings"] == ["w"]


def test_a_name_that_doesnt_resolve_refuses_the_run_naming_its_host() -> None:
    spec = {"hosts": [{"host": "web3", "address": "db3.corp", "required": True}]}
    resolve = _resolver({"db3.corp": "Name or service not known"})
    with pytest.raises(egress.EgressRefused) as refused:
        egress.resolve_allowlist(spec, resolver=resolve)
    assert str(refused.value) == (
        "its inventory restricts network egress, and web3's address db3.corp doesn't resolve "
        "here (Name or service not known)"
    )
    for spec in (
        {"jump_hosts": [{"host": "b", "address": "gone.lan", "port": 22}]},
        {"extras": [{"target": "gone.lan", "ports": None}]},
    ):
        with pytest.raises(egress.EgressRefused, match=r"gone\.lan doesn't resolve here"):
            egress.resolve_allowlist(spec, resolver=_resolver({"gone.lan": "nope"}))


def test_resolution_has_a_deadline() -> None:
    gate = threading.Event()

    def slow(name: str, port: int) -> frozenset:
        gate.wait(5)
        return frozenset()

    spec = {"hosts": [{"host": "h", "address": "slow.lan", "required": True}]}
    try:
        with pytest.raises(egress.EgressRefused, match=r"took longer than 0 s \(slow.lan\)"):
            egress.resolve_allowlist(spec, resolver=slow, seconds=0.2)
    finally:
        gate.set()


def test_too_many_addresses_refuse_the_run(monkeypatch) -> None:
    monkeypatch.setattr(egress, "MAX_ALLOWED_ADDRESSES", 1)
    spec = {"hosts": [{"host": "h", "address": "192.0.2.1"}, {"host": "i", "address": "192.0.2.2"}]}
    with pytest.raises(egress.EgressRefused, match="to 2 addresses, more than 1"):
        egress.resolve_allowlist(spec)


def test_resolvers_come_from_resolv_conf(tmp_path) -> None:
    conf = tmp_path / "resolv.conf"
    conf.write_text(
        "# Docker\nnameserver 127.0.0.11\nnameserver 192.168.65.7\nnameserver fe80::1%eth0\n"
        "nameserver nonsense\nsearch lan\noptions ndots:0\n"
    )
    assert egress.read_resolvers(str(conf)) == [
        ipaddress.ip_address("192.168.65.7"),
        ipaddress.ip_address("fe80::1"),
    ]
    assert egress.read_resolvers(str(tmp_path / "missing")) == []


def test_allow_and_release_touch_only_that_slots_table() -> None:
    net = FakeNet("172.20.0.2")
    egress_filter = _filter(net, ipv6=True)
    egress_filter.allow(identity_for_slot(5), _allowlist(hosts=(NET("192.0.2.1/32"),)))
    egress_filter.release(identity_for_slot(5))
    allow, release = net.applied
    assert "table inet ansideck_egress_slot5 {" in allow and "meta skuid 20005 jump" in allow
    assert (
        release == "add table inet ansideck_egress_slot5\ndelete table inet ansideck_egress_slot5\n"
    )
    assert net.installed == []  # the blocklist wasn't touched


def test_start_removes_slot_tables_an_earlier_worker_left() -> None:
    net = FakeNet("172.20.0.2")
    _filter(net, ipv6=False).start()
    (script,) = net.applied
    assert "delete table ip ansideck_egress_slot0\n" in script
    assert f"delete table ip ansideck_egress_slot{egress.MAX_SLOTS - 1}\n" in script


def test_refused_destinations_are_parsed_from_nft_json() -> None:
    listing = json.dumps({"nftables": [
        {"metainfo": {"version": "1.1.3"}},
        {"set": {"family": "inet", "name": "refused4", "elem": [
            {"concat": ["203.0.113.5", "tcp", 443]},
            {"elem": {"val": {"concat": ["198.51.100.1", "udp", 53]}}},
            {"concat": ["not an address", "tcp", 1]},
            {"concat": ["192.0.2.1", "icmp", 0]},
            {"concat": ["192.0.2.1", "tcp", 70000]},
        ]}},
    ]})  # fmt: skip
    assert egress.parse_refused(listing) == [
        {"address": "203.0.113.5", "protocol": "tcp", "port": 443},
        {"address": "198.51.100.1", "protocol": "udp", "port": 53},
    ]
    assert egress.parse_refused("") == [] and egress.parse_refused("[]") == []


class AllowlistProber:
    """Answers test_allowlists()'s probes in order."""

    def __init__(self, *answers: dict) -> None:
        self.answers = list(answers)

    def __call__(self, command: list[str]) -> dict:
        return self.answers.pop(0)


def _allowlist_tested(prober, refused_ports=None, *, fail=False):
    net = FakeNet("172.20.0.2")
    net.fail_install = fail
    listed: list = []

    def lister(table: str, name: str, *, ipv6: bool) -> str:
        listed.append((table, name))
        if refused_ports is None or name != "refused4":
            return ""
        elements = [{"concat": ["127.0.0.1", "tcp", port]} for port in refused_ports]
        return json.dumps({"nftables": [{"set": {"elem": elements}}]})

    egress_filter = EgressFilter(
        API, resolver=net.resolve, installer=net.install, applier=net.apply, prober=prober,
        lister=lister, ipv6=False,
    )  # fmt: skip
    egress_filter.addresses = frozenset({ipaddress.ip_address("172.20.0.2")})
    return egress_filter, net


def test_the_allowlist_self_test_passes_and_fails_as_it_should(monkeypatch) -> None:
    ports = iter([40001, 40002])

    class Server:
        def __init__(self, *_args, **_kwargs) -> None:
            self.port = next(ports)

        def getsockname(self):
            return ("127.0.0.1", self.port)

        def __enter__(self):
            return self

        def __exit__(self, *exc) -> None:
            pass

    def servers() -> None:
        nonlocal ports
        ports = iter([40001, 40002])
        monkeypatch.setattr(egress.socket, "create_server", Server)

    good = [
        {"resolved": "ok", "connect": ["connected", "ECONNREFUSED", "ECONNREFUSED"]},
        {"resolved": "ok", "connect": ["connected"]},
        {"resolved": "ok", "connect": ["connected"]},
    ]
    servers()
    egress_filter, net = _allowlist_tested(AllowlistProber(*good), refused_ports=[40002])
    assert egress_filter.test_allowlists(identity_for_slot(2)) is None
    assert net.applied[-1].endswith("delete table ip ansideck_egress_slot2\n")  # released

    servers()
    leaky = [{"resolved": "ok", "connect": ["connected", "connected", "ECONNREFUSED"]}]
    egress_filter, _ = _allowlist_tested(AllowlistProber(*leaky), refused_ports=[])
    assert "an allowlist didn't work for ansideck-run2: got connected, connected" in (
        egress_filter.test_allowlists(identity_for_slot(2))
    )

    servers()
    egress_filter, _ = _allowlist_tested(AllowlistProber(*good), refused_ports=[])
    assert egress_filter.test_allowlists(identity_for_slot(2)) == (
        "a connection ansideck-run2 was refused wasn't recorded"
    )

    servers()
    egress_filter, _ = _allowlist_tested(AllowlistProber(*good), fail=True)
    assert egress_filter.test_allowlists(identity_for_slot(2)) == "nft broke"
