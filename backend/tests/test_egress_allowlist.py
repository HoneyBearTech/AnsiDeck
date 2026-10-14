"""Where a restricted run's connections go (app.egress_allowlist): the API's side of egress
allowlists, before the worker looks names up (tests/test_egress.py)."""

import pytest

from app.egress_allowlist import (
    Hop,
    egress_target,
    egress_targets,
    job_egress,
    parse_extra,
    parse_extras,
    parse_jump_hosts,
)

CONN = "ansible_connection"


def _graph(hosts: dict, groups: dict | None = None, all_vars: dict | None = None) -> dict:
    groups = groups or {}
    for group in groups.values():
        group.setdefault("children", [])
        group.setdefault("vars", {})
    return {"vars": all_vars or {}, "hosts": hosts, "groups": groups}


@pytest.mark.parametrize(
    ("host_vars", "address"),
    [
        ({}, "web1"),
        ({"ansible_host": "10.0.0.5"}, "10.0.0.5"),
        ({"ansible_host": "a.lan", "ansible_ssh_host": "b.lan"}, "b.lan"),
        ({CONN: "winrm", "ansible_host": "a.lan", "ansible_winrm_host": "w.lan"}, "w.lan"),
        ({"ansible_connection": "ansible.builtin.psrp", "ansible_psrp_host": "p.lan"}, "p.lan"),
        ({CONN: "ansible.netcommon.network_cli", "ansible_host": "SW1.Lan."}, "sw1.lan"),
        ({"ansible_connection": "libssh", "ansible_libssh_host": "l.lan"}, "l.lan"),
        ({"ansible_host": "[2001:db8::1]"}, "2001:db8::1"),
    ],
)  # fmt: skip
def test_hosts_connect_where_their_connection_plugin_would(host_vars, address) -> None:
    target = egress_target("web1", host_vars)
    assert (target.status, target.address) == ("ok", address)
    assert target.required


def test_local_hosts_need_no_address() -> None:
    for connection in ("local", "ansible.builtin.local"):
        target = egress_target("localhost", {"ansible_connection": connection})
        assert (target.status, target.address) == ("local", None)


@pytest.mark.parametrize(
    ("host_vars", "reason"),
    [
        ({"ansible_connection": "{{ conn }}"}, "its connection is set by a template"),
        ({"ansible_connection": "community.docker.docker"},
         "connects with community.docker.docker, whose address AnsiDeck can't tell"),
        ({"ansible_host": "{{ lookup('env', 'X') }}"}, "its address is set by a template"),
        ({"ansible_host": "not a host"}, "its address isn't a plain host name"),
        ({"ansible_host": ["a", "b"]}, "its address isn't a plain host name"),
    ],
)  # fmt: skip
def test_templated_or_unknown_connections_make_the_address_unknown(host_vars, reason) -> None:
    target = egress_target("web1", host_vars)
    assert (target.status, target.reason) == ("unknown", reason)


def test_extra_vars_outrank_inventory_vars() -> None:
    graph = _graph({"web1": {"ansible_host": "inventory.lan"}})
    assert egress_targets(graph)["web1"].address == "inventory.lan"
    assert egress_targets(graph, None, {"ansible_host": "extra.lan"})["web1"].address == "extra.lan"


def test_group_vars_count_like_in_ansible() -> None:
    graph = _graph(
        {"web1": None, "web2": {"ansible_host": "own.lan"}},
        {"web": {"hosts": ["web1", "web2"], "vars": {"ansible_host": "group.lan"}}},
    )
    targets = egress_targets(graph)
    assert (targets["web1"].address, targets["web2"].address) == ("group.lan", "own.lan")


@pytest.mark.parametrize(
    ("args", "hop"),
    [
        ("-J bastion.lan", Hop("bastion.lan")),
        ("-Jjump@bastion.lan:2222", Hop("bastion.lan", 2222)),
        ("-o ProxyJump=admin@b.lan,second.lan", Hop("b.lan")),
        ("-oProxyJump=b.lan:2200", Hop("b.lan", 2200)),
        ('-o "ProxyJump b.lan" -o StrictHostKeyChecking=no', Hop("b.lan")),
        ("-o proxyjump=ssh://u@[2001:db8::9]:2022", Hop("2001:db8::9", 2022)),
        ("-o ProxyJump=none", None),
        ("-C -o ControlMaster=auto", None),
    ],
)
def test_jump_hosts_are_read_from_every_spelling_of_dash_j_and_proxyjump(args, hop) -> None:
    assert parse_jump_hosts(args) == (hop, False, False)


def test_only_the_first_hop_is_allowed_and_hosts_behind_it_need_not_resolve() -> None:
    target = egress_target(
        "inner", {"ansible_host": "inner.corp", "ansible_ssh_common_args": "-J b1.lan,b2.lan"}
    )
    assert (target.status, target.jump, target.required) == ("indirect", Hop("b1.lan"), False)
    graph = _graph({"inner": {"ansible_host": "inner.corp", "ansible_ssh_extra_args": "-J b1.lan"}})
    spec = job_egress(graph, None, None, None)
    assert spec["hosts"] == [{"host": "inner", "address": "inner.corp", "required": False}]
    assert spec["jump_hosts"] == [{"host": "inner", "address": "b1.lan", "port": 22}]


def test_proxy_commands_and_templated_ssh_args_are_warnings_not_refusals() -> None:
    for host_vars in (
        {"ansible_ssh_common_args": "-o ProxyCommand='ssh -W %h:%p b.lan'"},
        {"ansible_ssh_common_args": "{{ my_args }}"},
        {"ansible_ssh_common_args": "-o 'unbalanced"},
        {"ansible_connection": "paramiko", "ansible_paramiko_proxy_command": "nc b.lan 22"},
    ):
        target = egress_target("h", host_vars)
        assert target.status == "indirect" and not target.required
        assert "refused unless the proxy is among the extra entries" in target.warnings[0]
    assert parse_jump_hosts("-o ProxyCommand=none") == (None, False, False)


@pytest.mark.parametrize(
    ("entry", "parsed"),
    [
        (("10.0.0.5", None), {"target": "10.0.0.5", "ports": None, "note": None}),
        (("10.0.0.0/24", "443"), {"target": "10.0.0.0/24", "ports": [[443, 443]], "note": None}),
        (("10.0.0.7/24", "any"), {"target": "10.0.0.0/24", "ports": None, "note": None}),
        (("::ffff:192.0.2.1", ""), {"target": "192.0.2.1", "ports": None, "note": None}),
        (("Mirror.LAN.", "80, 443,8000-8100,8050-8200"),
         {"target": "mirror.lan", "ports": [[80, 80], [443, 443], [8000, 8200]], "note": None}),
        (("pypi.org", "443", " packages "),
         {"target": "pypi.org", "ports": [[443, 443]], "note": "packages"}),
    ],
)  # fmt: skip
def test_extras_accept_addresses_networks_and_names_with_ports(entry, parsed) -> None:
    assert parse_extra(*entry) == parsed


@pytest.mark.parametrize(
    ("entry", "problem"),
    [
        (("0.0.0.0/0", None), "every address"),
        (("::/0", None), "every address"),
        (("169.254.169.254", None), "always blocked"),
        (("fe80::1", None), "always blocked"),
        (("*.example.com", None), "isn't an address"),
        (("bad host", None), "isn't an address"),
        (("", None), "is required"),
        (("a.lan", "0"), "between 1 and 65535"),
        (("a.lan", "70000"), "between 1 and 65535"),
        (("a.lan", "443-80"), "between 1 and 65535"),
        (("a.lan", "http"), "isn't a port"),
        (("a.lan", ",".join(str(p) for p in range(1, 22))), "at most 20"),
    ],
)
def test_extras_refuse_everything_and_always_blocked_networks(entry, problem) -> None:
    with pytest.raises(ValueError, match=problem):
        parse_extra(*entry)


def test_extras_are_numbered_in_errors_and_deduplicated() -> None:
    entries = [{"target": "a.lan", "ports": "443"}, {"target": "A.lan.", "ports": "443"}]
    assert parse_extras(entries) == [{"target": "a.lan", "ports": [[443, 443]], "note": None}]
    with pytest.raises(ValueError, match=r"^entry 2: "):
        parse_extras([{"target": "a.lan"}, {"target": "0.0.0.0/0"}])
    with pytest.raises(ValueError, match="at most 200"):
        parse_extras([{"target": f"h{i}.lan"} for i in range(201)])


def test_the_target_group_is_allowlisted_not_the_limit() -> None:
    graph = _graph(
        {"web1": None, "web2": None, "db1": None},
        {"web": {"hosts": ["web1", "web2"]}, "db": {"hosts": ["db1"]}},
    )
    spec = job_egress(graph, "web", None, [{"target": "10.0.0.0/8", "ports": None, "note": "x"}])
    assert [h["host"] for h in spec["hosts"]] == ["web1", "web2"]
    assert spec["extras"] == [{"target": "10.0.0.0/8", "ports": None}]
    assert {h["host"] for h in job_egress(graph, None, None, None)["hosts"]} == {
        "web1",
        "web2",
        "db1",
    }


def test_an_unknown_address_fails_the_job_naming_the_hosts() -> None:
    hosts = {"web1": {"ansible_host": "{{ x }}"}, "ok": None}
    hosts |= {f"dc{i}": {"ansible_connection": "community.docker.docker"} for i in range(6)}
    with pytest.raises(ValueError, match="restricts network egress") as refused:
        job_egress(_graph(hosts), None, None, None)
    message = str(refused.value)
    assert message.startswith(
        "its inventory restricts network egress, and the address of 7 hosts isn't known: "
        "dc0 (connects with community.docker.docker, whose address AnsiDeck can't tell), "
    )
    assert message.endswith(", and 2 more")
    with pytest.raises(ValueError, match=r"the address of 1 host isn't known: web1 \(its address"):
        job_egress(_graph({"web1": {"ansible_host": "{{ x }}"}}), None, None, None)
