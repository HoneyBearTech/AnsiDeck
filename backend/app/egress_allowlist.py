"""Restricting a run's network egress to its inventory's hosts (the API's side).

An inventory can restrict its runs: the worker then limits the run's slot user to the hosts'
addresses (any port), the first jump host of each (its ssh port), the inventory's extra
entries and DNS (app.worker.egress). Here the job's `egress` part is worked out: where each host
the run targets connects to, by its connection plugin's own variables (extra vars over the
inventory's, like ansible), and which jump hosts its ssh arguments name. Names are looked up by
the worker, which sees what the run sees.

A host whose address can't be known before the run starts (set by a template, or a connection
plugin AnsiDeck can't read) fails the run without running it: an allowlist that might miss a
host is no use. A proxy command or ssh arguments AnsiDeck can't read aren't refused: their
connections fail closed unless the proxy is listed among the extra entries.

The target group's hosts are allowed whatever `--limit` says: limits are patterns, and
`delegate_to` reaches hosts outside them. Vars from a repository's group_vars/host_vars and
hosts a playbook adds (add_host) aren't seen: list them as extra entries.
"""

import ipaddress
import re
import shlex
from dataclasses import dataclass, field

from app.host_keys import merged_host_vars
from app.inventory_render import target_hosts
from app.worker.egress import ALWAYS_BLOCKED, METADATA_NETWORKS

MAX_EXTRAS = 200
MAX_PORT_RANGES = 20
MAX_NOTE = 200
MAX_NAMED = 5

LOCAL_CONNECTIONS = frozenset({"local", "ansible.builtin.local"})
_SSH = ("ansible_host", "ansible_ssh_host")
_NETWORK = ("ansible_host",)
_NETWORK_PLUGINS = (
    "network_cli",
    "netconf",
    "httpapi",
    "ansible.netcommon.network_cli",
    "ansible.netcommon.netconf",
    "ansible.netcommon.httpapi",
)
# Connection plugins whose address AnsiDeck can tell, with the variables that set it (the last
# one set wins, as in each plugin's documentation).
ADDRESS_VARS: dict[str, tuple[str, ...]] = {
    **dict.fromkeys(("ssh", "smart", "ansible.builtin.ssh"), _SSH),
    **dict.fromkeys(("paramiko", "paramiko_ssh", "ansible.builtin.paramiko_ssh"), _SSH),
    **dict.fromkeys(("winrm", "ansible.builtin.winrm"), ("ansible_host", "ansible_winrm_host")),
    **dict.fromkeys(("psrp", "ansible.builtin.psrp"), ("ansible_host", "ansible_psrp_host")),
    **dict.fromkeys(_NETWORK_PLUGINS, _NETWORK),
    **dict.fromkeys(("libssh", "ansible.netcommon.libssh"), (*_SSH, "ansible_libssh_host")),
}
# Plugins that run ssh itself, whose arguments can name a jump host.
SSH_CONNECTIONS = frozenset({"ssh", "smart", "ansible.builtin.ssh"})
SSH_ARG_VARS = ("ansible_ssh_common_args", "ansible_ssh_extra_args", "ansible_ssh_args")
PROXY_COMMAND_VARS = (
    "ansible_paramiko_proxy_command",
    "ansible_netconf_proxy_command",
    "ansible_libssh_proxy_command",
)

_HOSTNAME = re.compile(
    r"(?=.{1,253}$)[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,62})(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,62}))*\.?"
)
_PORTS = re.compile(r"\s*(\d{1,5})\s*(?:-\s*(\d{1,5})\s*)?")


@dataclass(frozen=True)
class Hop:
    host: str
    port: int = 22


@dataclass
class EgressTarget:
    """Where a host's connections go. status: ok (its address is allowed), local (no network),
    indirect (through a jump host or a proxy; its address needn't resolve on the worker) or
    unknown (its runs are refused)."""

    host: str
    connection: str
    status: str
    address: str | None = None
    jump: Hop | None = None
    reason: str | None = None
    warnings: list[str] = field(default_factory=list)

    @property
    def required(self) -> bool:
        return self.status == "ok"


def _templated(value) -> bool:
    return isinstance(value, str) and ("{{" in value or "{%" in value)


def plain_address(value) -> str | None:
    """`value` as an IP address or host name, or None."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    try:
        return str(ipaddress.ip_address(value.strip("[]")))
    except ValueError:
        pass
    return value.lower().rstrip(".") if _HOSTNAME.fullmatch(value) else None


def _hop(spec: str) -> Hop | None:
    """The first hop of a ProxyJump/-J value ([user@]host[:port], ssh://..., [v6]:port)."""
    first = spec.split(",")[0].strip()
    if not first or first.lower() == "none":
        return None
    first = first.removeprefix("ssh://").rsplit("@", 1)[-1]
    port = 22
    if first.startswith("["):
        host, _, rest = first[1:].partition("]")
        if rest.startswith(":"):
            port = int(rest[1:])
    elif first.count(":") == 1:
        host, _, number = first.partition(":")
        port = int(number)
    else:
        host = first
    address = plain_address(host)
    if address is None or not 0 < port < 65536:
        raise ValueError(spec)
    return Hop(address, port)


def parse_jump_hosts(args: str) -> tuple[Hop | None, bool, bool]:
    """(the first jump hop, whether a ProxyCommand is set, whether the arguments couldn't be
    read) for ssh arguments as ansible passes them."""
    if _templated(args):
        return None, False, True
    try:
        tokens = shlex.split(args)
    except ValueError:
        return None, False, True
    hop, proxy = None, False
    options: list[str] = []
    jumps: list[str] = []
    i = 0
    while i < len(tokens):
        arg = tokens[i]
        if arg in ("-J", "-o") and i + 1 < len(tokens):
            (jumps if arg == "-J" else options).append(tokens[i + 1])
            i += 2
            continue
        if arg.startswith("-J") and len(arg) > 2:
            jumps.append(arg[2:])
        elif arg.startswith("-o") and len(arg) > 2:
            options.append(arg[2:])
        i += 1
    for option in options:
        name, _, value = option.replace("=", " ", 1).partition(" ")
        name = name.strip().lower()
        if name == "proxyjump":
            jumps.append(value.strip())
        elif name == "proxycommand" and value.strip().lower() != "none":
            proxy = True
    try:
        for spec in jumps:
            hop = hop or _hop(spec)
    except ValueError:
        return None, proxy, True
    return hop, proxy, False


def egress_target(host: str, host_vars: dict) -> EgressTarget:
    connection = host_vars.get("ansible_connection") or "ssh"
    if not isinstance(connection, str) or _templated(connection):
        return EgressTarget(host, "?", "unknown", reason="its connection is set by a template")
    if connection in LOCAL_CONNECTIONS:
        return EgressTarget(host, connection, "local")
    names = ADDRESS_VARS.get(connection)
    if names is None:
        return EgressTarget(
            host,
            connection,
            "unknown",
            reason=f"connects with {connection}, whose address AnsiDeck can't tell",
        )
    value = host
    for name in names:
        if host_vars.get(name) not in (None, ""):
            value = host_vars[name]
    if _templated(value):
        return EgressTarget(host, connection, "unknown", reason="its address is set by a template")
    address = plain_address(value)
    if address is None:
        return EgressTarget(
            host, connection, "unknown", reason="its address isn't a plain host name"
        )
    target = EgressTarget(host, connection, "ok", address=address)
    proxy = any(host_vars.get(name) not in (None, "") for name in PROXY_COMMAND_VARS)
    unreadable = False
    if connection in SSH_CONNECTIONS:
        for name in SSH_ARG_VARS:
            args = host_vars.get(name)
            if args in (None, ""):
                continue
            if not isinstance(args, str):
                unreadable = True
                continue
            hop, proxied, unread = parse_jump_hosts(args)
            target.jump = target.jump or hop
            proxy, unreadable = proxy or proxied, unreadable or unread
    if target.jump is not None:
        target.status = "indirect"
    if proxy or unreadable:
        target.status = "indirect"
        why = "a proxy command" if proxy else "ssh arguments AnsiDeck can't read"
        target.warnings.append(
            f"{host} connects with {why}: its connections are refused unless the proxy is "
            "among the extra entries"
        )
    return target


def egress_targets(
    graph: dict, hosts: set[str] | None = None, extra_vars: dict | None = None
) -> dict[str, EgressTarget]:
    """Each host's (or each of `hosts`') egress target; extra vars win over the inventory's."""
    from ansible.utils.vars import combine_vars

    merged = merged_host_vars(graph)
    wanted = sorted(merged if hosts is None else hosts & merged.keys())
    extra = extra_vars or {}
    return {host: egress_target(host, combine_vars(merged[host], extra)) for host in wanted}


def unknown_message(unknown: list[EgressTarget]) -> str:
    named = ", ".join(f"{t.host} ({t.reason})" for t in unknown[:MAX_NAMED])
    if len(unknown) > MAX_NAMED:
        named += f", and {len(unknown) - MAX_NAMED} more"
    count = "1 host isn't" if len(unknown) == 1 else f"{len(unknown)} hosts isn't"
    return f"its inventory restricts network egress, and the address of {count} known: {named}"


def job_egress(graph: dict, group_name: str | None, extra_vars: dict | None, extras) -> dict:
    """The job's `egress` part (app.worker.egress.resolve_allowlist). Raises ValueError (its
    message safe to show) when a host's address isn't known."""
    hosts = target_hosts(graph, group_name) if group_name is not None else set(graph["hosts"])
    targets = list(egress_targets(graph, hosts, extra_vars).values())
    unknown = [t for t in targets if t.status == "unknown"]
    if unknown:
        raise ValueError(unknown_message(unknown))
    jumps: dict[Hop, str] = {}
    warnings: list[str] = []
    spec_hosts = []
    for target in targets:
        if target.address is not None:
            spec_hosts.append(
                {"host": target.host, "address": target.address, "required": target.required}
            )
        if target.jump is not None:
            jumps.setdefault(target.jump, target.host)
        warnings += target.warnings
    return {
        "hosts": spec_hosts,
        "jump_hosts": [
            {"host": host, "address": hop.host, "port": hop.port} for hop, host in jumps.items()
        ],
        "extras": [{"target": e["target"], "ports": e.get("ports")} for e in extras or []],
        "warnings": warnings[:50],
    }


def _parse_ports(text: str) -> list[list[int]]:
    ranges = []
    for part in text.split(","):
        match = _PORTS.fullmatch(part)
        if match is None:
            raise ValueError(f"{part.strip()!r} isn't a port or a range like 8000-8100")
        lo = int(match[1])
        hi = int(match[2] or lo)
        if not 1 <= lo <= hi <= 65535:
            raise ValueError(f"{part.strip()} isn't a port range between 1 and 65535")
        ranges.append([lo, hi])
    if len(ranges) > MAX_PORT_RANGES:
        raise ValueError(f"at most {MAX_PORT_RANGES} ports or ranges")
    merged: list[list[int]] = []
    for lo, hi in sorted(ranges):
        if merged and lo <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], hi)
        else:
            merged.append([lo, hi])
    return merged


def _network(text: str):
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None
    if isinstance(network, ipaddress.IPv6Network) and network.prefixlen >= 96:
        mapped = network.network_address.ipv4_mapped
        if mapped is not None:
            network = ipaddress.IPv4Network(f"{mapped}/{network.prefixlen - 96}")
    return network


def parse_extra(target, ports, note=None) -> dict:
    """An extra entry as stored: {"target", "ports": [[lo, hi], ...] | None, "note"}. Raises
    ValueError saying why it can't be one."""
    if not isinstance(target, str) or not target.strip():
        raise ValueError("an address, a network (CIDR) or a host name is required")
    target = target.strip()
    network = _network(target)
    if network is not None:
        if network.prefixlen == 0:
            raise ValueError("that's every address: turn the restriction off instead")
        blocked = (*METADATA_NETWORKS, *ALWAYS_BLOCKED)
        if any(
            network.version == b.version and network.subnet_of(b)  # type: ignore[arg-type]
            for b in blocked
        ):
            raise ValueError(f"{network} is always blocked for runs")
        target = str(network) if network.num_addresses > 1 else str(network.network_address)
    elif "*" in target or not _HOSTNAME.fullmatch(target):
        raise ValueError(f"{target!r} isn't an address, a network or a host name")
    else:
        target = target.lower().rstrip(".")
    parsed_ports = None
    if ports is not None and str(ports).strip() not in ("", "any", "*"):
        parsed_ports = _parse_ports(str(ports))
    if note is not None and (not isinstance(note, str) or len(note) > MAX_NOTE):
        raise ValueError(f"a note is text of at most {MAX_NOTE} characters")
    return {"target": target, "ports": parsed_ports, "note": (note or "").strip() or None}


def parse_extras(entries: list) -> list[dict]:
    """Every entry parsed (ValueError "entry N: why"), without duplicates."""
    if len(entries) > MAX_EXTRAS:
        raise ValueError(f"at most {MAX_EXTRAS} extra entries")
    parsed: list[dict] = []
    for number, entry in enumerate(entries, start=1):
        try:
            item = parse_extra(entry.get("target"), entry.get("ports"), entry.get("note"))
        except ValueError as exc:
            raise ValueError(f"entry {number}: {exc}") from None
        if not any(p["target"] == item["target"] and p["ports"] == item["ports"] for p in parsed):
            parsed.append(item)
    return parsed
