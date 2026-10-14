"""Keeps runs away from the API and cloud metadata (the worker's egress filter), and, for
inventories that ask for it, limits a run to its inventory's hosts (per-slot allowlists).

Runs, inventory refreshes and playbook checks share the worker container's network, but they
run as the slot users (app.run_isolation), and only the worker itself (uid 0) talks to the API.
So the worker installs an nftables table in its network namespace that rejects every
connection from a slot user to:

- the API's addresses, on any port (the public API, the internal worker API, metrics);
- cloud metadata services (the host's cloud identity), unless WORKER_ALLOW_CLOUD_METADATA;
- IPv6 link-local addresses (the API has one, which a lookup doesn't return);
- WORKER_BLOCKED_NETWORKS.

TCP gets a reset, so a blocked connection fails at once instead of hanging; anything else an
ICMP "administratively prohibited". Slot processes can't change the table: they have no
capabilities and can't gain any. Only this table is ever replaced (one nft transaction), never
the whole ruleset: Docker's DNS forwarding lives in the same network namespace.

The API's address changes when its container is recreated, so the worker looks it up again
every few seconds and updates the table; it keeps CAP_NET_ADMIN for that, which reaches only
the container's own network namespace. self_test() checks, before any run, that a slot user
really is refused while the worker gets through.

Allowlists: a run on an inventory that restricts egress gets a table of its own slot,
`ansideck_egress_slot<n>`, installed before anything of the run starts and deleted only after
the slot was swept (until then ssh's ControlPersist masters and whatever the playbook left
running could still use the network). Its uid may then reach only:

- DNS: Docker's resolver (127.0.0.11, whose port 53 Docker's own nat rule rewrites before this
  hook, hence `ct original proto-dst`) and the nameservers in /etc/resolv.conf;
- the inventory's hosts, on any port and protocol (the run controls them anyway);
- the first jump host, on its ssh port; the inventory's extra entries, on their ports.

Everything else, ICMP included (Docker lets anyone ping), is rejected at once and recorded
(the first 256 destinations) for the run page. The blocklist above still wins: a reject is
final, wherever the accept is. The slot's uid is matched positively (`meta skuid N jump`):
with `!= N accept` the TCP resets the rejects send, which have no socket, would be rejected in
turn and every refused connection would hang. test_allowlists() checks all of this at startup.

Imports only the standard library, app.run_isolation and app.run_executor (see app.worker).
"""

import concurrent.futures
import contextlib
import ipaddress
import itertools
import json
import logging
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from app.run_executor import run_child
from app.run_isolation import MAX_SLOTS, RUN_UID_BASE, RunIdentity, effective_caps, wrap

logger = logging.getLogger(__name__)

Address = ipaddress.IPv4Address | ipaddress.IPv6Address
Network = ipaddress.IPv4Network | ipaddress.IPv6Network

TABLE = "ansideck_egress"
NET_ADMIN_BIT = 12  # linux/capability.h
NFT_FALLBACK = "/usr/sbin/nft"  # not on the PATH docker-compose.yml gives the worker
REFRESH_SECONDS = 5.0
# Every slot user the image has, not just the configured slots.
FIRST_UID, LAST_UID = RUN_UID_BASE, RUN_UID_BASE + MAX_SLOTS - 1
METADATA_NETWORKS: tuple[Network, ...] = tuple(
    ipaddress.ip_network(network)
    for network in (
        "169.254.0.0/16",  # AWS, Azure, GCP, OCI, OpenStack, DigitalOcean, Hetzner, ECS, EKS
        "100.100.100.200/32",  # Alibaba Cloud
        "fd00:ec2::254/128",  # AWS (IPv6)
        "fd00:ec2::23/128",  # AWS EKS Pod Identity (IPv6)
        "fd20:ce::254/128",  # GCP (IPv6)
        "fd00:c1::a9fe:a9fe/128",  # OCI (IPv6)
        "64:ff9b::a9fe:0/112",  # 169.254.0.0/16 through NAT64
        "64:ff9b::6464:64c8/128",  # 100.100.100.200 through NAT64
    )
)
ALWAYS_BLOCKED: tuple[Network, ...] = (ipaddress.ip_network("fe80::/10"),)
# Docker's DNS server: blocking it would break every name lookup in runs.
_DOCKER_DNS = ipaddress.ip_address("127.0.0.11")
_METADATA_PROBE = ("169.254.169.254", 80)
_NFT_TIMEOUT_SECONDS = 10
_PROBE_TIMEOUT_SECONDS = 3.0
_PROBE_ATTEMPTS = 3
SLOT_TABLE = TABLE + "_slot{}"
MAX_ALLOWED_ADDRESSES = 20000
REFUSED_SET_SIZE = 256
_RESOLVE_SECONDS = 60.0
_RESOLVE_THREADS = 16
_PROTOCOLS = ("tcp", "udp")

# Run as the worker and as slot users: connects to each target and reports how it went.
_PROBE = """
import errno, json, socket, sys
args = json.loads(sys.argv[1])
out = {"resolved": None, "connect": []}
if args["name"]:
    try:
        socket.getaddrinfo(args["name"], None)
        out["resolved"] = "ok"
    except OSError as exc:
        out["resolved"] = str(exc)
for host, port in args["targets"]:
    try:
        socket.create_connection((host, port), args["timeout"]).close()
        result = "connected"
    except TimeoutError:
        result = "timeout"
    except OSError as exc:
        result = errno.errorcode.get(exc.errno, str(exc))
    out["connect"].append(result)
print(json.dumps(out))
"""


class EgressError(Exception):
    """nft refused the table, or could not be run."""


class EgressRefused(Exception):
    """A run's allowlist can't be built (a name doesn't resolve...); the message is shown."""


@dataclass(frozen=True)
class Allowlist:
    """What one run's slot may reach: `hosts` on any port and protocol, `ports` as
    (network, protocol, first port, last port); `report` is what the run page shows."""

    hosts: tuple[Network, ...] = ()
    ports: tuple[tuple[Network, str, int, int], ...] = ()
    report: dict = field(default_factory=dict)


def _unmapped(network: Network) -> Network:
    """An IPv4-mapped IPv6 network (::ffff:a.b.c.d/n) as the IPv4 network it is: such
    connections leave as IPv4 packets."""
    if isinstance(network, ipaddress.IPv6Network) and network.prefixlen >= 96:
        mapped = network.network_address.ipv4_mapped
        if mapped is not None:
            return ipaddress.IPv4Network(f"{mapped}/{network.prefixlen - 96}")
    return network


def parse_networks(text: str) -> list[Network]:
    """WORKER_BLOCKED_NETWORKS: comma-separated addresses or networks (CIDR)."""
    networks = []
    for item in (part.strip() for part in text.split(",")):
        if not item:
            continue
        try:
            network = _unmapped(ipaddress.ip_network(item, strict=False))
        except ValueError:
            raise ValueError(f"{item!r} is not an IP address or network") from None
        if _DOCKER_DNS in network:
            raise ValueError(f"{item} would block DNS for runs ({_DOCKER_DNS}, Docker's resolver)")
        networks.append(network)
    return networks


def api_endpoint(url: str) -> tuple[str, int]:
    """The host and port in ANSIDECK_API_URL."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"ANSIDECK_API_URL must be an http(s) URL with a host, not {url!r}")
    return parts.hostname, parts.port or (443 if parts.scheme == "https" else 80)


def resolve(host: str, port: int) -> frozenset[Address]:
    """Every address `host` has now. Raises OSError if it can't be looked up."""
    try:
        addresses = [ipaddress.ip_address(host)]
    except ValueError:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        addresses = [ipaddress.ip_address(str(info[4][0]).split("%")[0]) for info in infos]
    return frozenset(_unmapped_address(address) for address in addresses)


def _unmapped_address(address: Address) -> Address:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def ruleset(networks: Iterable[Network], *, ipv6: bool = True) -> str:
    """The nft script that replaces our table (and nothing else) with one rejecting slot
    users' traffic to `networks`. Without IPv6 (a kernel booted with ipv6.disable=1) the
    table is IPv4 only."""
    networks = [_unmapped(network) for network in networks]
    family = "inet" if ipv6 else "ip"
    uids = f"{FIRST_UID}-{LAST_UID}"
    lines = [f"add table {family} {TABLE}", f"delete table {family} {TABLE}"]
    lines.append(f"table {family} {TABLE} {{")
    sets = [("blocked4", "ipv4_addr", "ip", ipaddress.IPv4Network)]
    if ipv6:
        sets.append(("blocked6", "ipv6_addr", "ip6", ipaddress.IPv6Network))
    for name, kind, _, cls in sets:
        found = list(ipaddress.collapse_addresses(n for n in networks if isinstance(n, cls)))
        elements = f" elements = {{ {', '.join(map(str, found))} }};" if found else ""
        lines.append(f"  set {name} {{ type {kind}; flags interval;{elements} }}")
    lines.append("  chain output {")
    lines.append("    type filter hook output priority filter; policy accept;")
    other = "icmpx admin-prohibited" if ipv6 else "icmp admin-prohibited"
    for name, _, match, _ in sets:
        selector = f"meta skuid {uids} {match} daddr @{name}"
        lines.append(f"    {selector} meta l4proto tcp counter reject with tcp reset")
        lines.append(f"    {selector} counter reject with {other}")
    lines.append("  }")
    lines.append("}")
    return "\n".join(lines) + "\n"


def _lookup_all(names: Iterable[str], resolver, seconds: float) -> dict[str, object]:
    """Each name's addresses (a frozenset) or why it didn't resolve (a str), in parallel,
    within `seconds` overall."""
    names = sorted(set(names))
    results: dict[str, object] = {}
    if not names:
        return results
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=min(_RESOLVE_THREADS, len(names)))
    try:
        futures = {pool.submit(resolver, name, 0): name for name in names}
        try:
            for future in concurrent.futures.as_completed(futures, timeout=seconds):
                name = futures[future]
                try:
                    results[name] = future.result()
                except OSError as exc:
                    results[name] = exc.strerror or str(exc)
        except concurrent.futures.TimeoutError:
            slow = sorted(name for future, name in futures.items() if not future.done())
            raise EgressRefused(
                f"looking up {len(slow)} names took longer than {seconds:.0f} s "
                f"({', '.join(slow[:3])}{', ...' if len(slow) > 3 else ''})"
            ) from None
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return results


def _target_network(target: str) -> Network | None:
    try:
        return _unmapped(ipaddress.ip_network(target, strict=False))
    except ValueError:
        return None


def resolve_allowlist(
    spec: dict, resolver: Callable[[str, int], frozenset[Address]] = resolve,
    seconds: float = _RESOLVE_SECONDS,
) -> Allowlist:  # fmt: skip
    """The addresses a restricted run may reach, from the job's `egress` (app.egress_allowlist):
    names are looked up here, as the worker, which sees the same resolv.conf and /etc/hosts as
    the run. Raises EgressRefused if a host the run connects to directly, a jump host or an
    extra entry doesn't resolve (a host behind a jump host or a proxy may not)."""
    hosts = list(spec.get("hosts") or [])
    jumps = list(spec.get("jump_hosts") or [])
    extras = list(spec.get("extras") or [])
    names = [h["address"] for h in hosts] + [j["address"] for j in jumps]
    names += [e["target"] for e in extras if _target_network(e["target"]) is None]
    found = _lookup_all(names, resolver, seconds)

    problems: list[str] = []
    unresolved: list[dict] = []
    host_networks: list[Network] = []
    port_entries: list[tuple[Network, str, int, int]] = []
    report: dict = {
        "hosts": [],
        "jump_hosts": [],
        "extras": [],
        "unresolved": unresolved,
        "warnings": list(spec.get("warnings") or []),
    }

    def addresses_of(name: str) -> list[Address] | str:
        result = found.get(name)
        if isinstance(result, frozenset):
            return sorted(result, key=lambda a: (a.version, a))
        return str(result or "no address")

    for host in hosts:
        result = addresses_of(host["address"])
        if isinstance(result, str):
            if host.get("required", True):
                problems.append(
                    f"{host['host']}'s address {host['address']} doesn't resolve here ({result})"
                )
            else:
                unresolved.append(
                    {"host": host["host"], "address": host["address"], "reason": result}
                )
            continue
        host_networks += [ipaddress.ip_network(a) for a in result]
        report["hosts"].append(
            {"host": host["host"], "address": host["address"], "addresses": list(map(str, result))}
        )
    for jump in jumps:
        result = addresses_of(jump["address"])
        if isinstance(result, str):
            problems.append(f"the jump host {jump['address']} doesn't resolve here ({result})")
            continue
        port = int(jump.get("port") or 22)
        port_entries += [(ipaddress.ip_network(a), "tcp", port, port) for a in result]
        report["jump_hosts"].append(
            {
                "host": jump.get("host"),
                "address": jump["address"],
                "port": port,
                "addresses": list(map(str, result)),
            }
        )
    for extra in extras:
        network = _target_network(extra["target"])
        if network is not None:
            networks = [network]
        else:
            result = addresses_of(extra["target"])
            if isinstance(result, str):
                problems.append(
                    f"the extra entry {extra['target']} doesn't resolve here ({result})"
                )
                continue
            networks = [ipaddress.ip_network(a) for a in result]
        ranges = extra.get("ports")
        if ranges is None:
            host_networks += networks
        else:
            port_entries += [
                (n, proto, int(lo), int(hi))
                for n in networks
                for proto in _PROTOCOLS
                for lo, hi in ranges
            ]
        report["extras"].append(
            {"target": extra["target"], "ports": ranges, "addresses": list(map(str, networks))}
        )

    if problems:
        shown = "; ".join(problems[:3]) + (
            f"; and {len(problems) - 3} more" if len(problems) > 3 else ""
        )
        raise EgressRefused(f"its inventory restricts network egress, and {shown}")
    count = len(host_networks) + len(port_entries)
    if count > MAX_ALLOWED_ADDRESSES:
        raise EgressRefused(
            f"its inventory restricts network egress to {count} addresses, more than "
            f"{MAX_ALLOWED_ADDRESSES}"
        )
    return Allowlist(hosts=tuple(host_networks), ports=tuple(port_entries), report=report)


def read_resolvers(path: str = "/etc/resolv.conf") -> list[Address]:
    """The nameservers a run asks (besides Docker's, which is always allowed)."""
    found: list[Address] = []
    try:
        with open(path, encoding="utf-8", errors="replace") as conf:
            lines = conf.read().splitlines()
    except OSError:
        return found
    for line in lines:
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "nameserver":
            try:
                address = _unmapped_address(ipaddress.ip_address(parts[1].split("%")[0]))
            except ValueError:
                continue
            if address != _DOCKER_DNS and address not in found:
                found.append(address)
    return found


def _span(network: Network) -> tuple[int, int]:
    return int(network.network_address), int(network.broadcast_address)


def _merge(ranges: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for lo, hi in sorted(ranges):
        if merged and lo <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    return merged


def _disjoint(
    hosts: list[Network], ports: list[tuple[Network, str, int, int]], version: int
) -> list[tuple[tuple[int, int], str, tuple[int, int]]]:
    """`ports` as non-overlapping (address range, protocol, port range) elements, which nft
    requires; entries inside a host network are dropped (the host allows every port)."""
    host_spans = _merge(_span(n) for n in hosts if n.version == version)

    def covered(lo: int, hi: int) -> bool:
        return any(a <= lo and hi <= b for a, b in host_spans)

    elements: list[tuple[tuple[int, int], str, tuple[int, int]]] = []
    for protocol in _PROTOCOLS:
        entries = [
            (*_span(n), lo, hi)
            for n, proto, lo, hi in ports
            if n.version == version and proto == protocol and not covered(*_span(n))
        ]
        # Cut the address space at every entry's ends; each piece gets the union of the port
        # ranges of the entries over it, and neighbouring pieces with the same ports join.
        cuts = sorted({lo for lo, _, _, _ in entries} | {hi + 1 for _, hi, _, _ in entries})
        pieces: list[tuple[int, int, tuple[tuple[int, int], ...]]] = []
        for start, after in itertools.pairwise(cuts):
            over = _merge(
                (plo, phi) for lo, hi, plo, phi in entries if lo <= start and after - 1 <= hi
            )
            if not over:
                continue
            if pieces and pieces[-1][1] + 1 == start and pieces[-1][2] == tuple(over):
                pieces[-1] = (pieces[-1][0], after - 1, pieces[-1][2])
            else:
                pieces.append((start, after - 1, tuple(over)))
        elements += [((lo, hi), protocol, ports) for lo, hi, ranges in pieces for ports in ranges]
    return elements


def _address_text(value: int, version: int) -> str:
    return str(ipaddress.ip_address(value) if version == 4 else ipaddress.IPv6Address(value))


def _range_text(lo: int, hi: int, version: int) -> str:
    if lo == hi:
        return _address_text(lo, version)
    return f"{_address_text(lo, version)}-{_address_text(hi, version)}"


def _port_text(lo: int, hi: int) -> str:
    return str(lo) if lo == hi else f"{lo}-{hi}"


def _slot_of(identity: RunIdentity) -> int:
    return identity.uid - RUN_UID_BASE


def slot_table(slot: int) -> str:
    return SLOT_TABLE.format(slot)


def slot_ruleset(
    slot: int, uid: int, allowlist: Allowlist, resolvers: Iterable[Address], *, ipv6: bool = True
) -> str:
    """The nft script that replaces slot `slot`'s table (and nothing else) with one limiting
    `uid` to `allowlist` plus DNS. Without IPv6 the table is IPv4 only."""
    family = "inet" if ipv6 else "ip"
    table = slot_table(slot)
    resolvers = [_unmapped_address(a) for a in resolvers]
    hosts = [_unmapped(n) for n in allowlist.hosts]
    ports = [(_unmapped(n), proto, lo, hi) for n, proto, lo, hi in allowlist.ports]
    versions = [(4, "ip", "ipv4_addr")] + ([(6, "ip6", "ipv6_addr")] if ipv6 else [])
    lines = [
        f"add table {family} {table}",
        f"delete table {family} {table}",
        f"table {family} {table} {{",
    ]
    for version, _, kind in versions:
        dns = [str(a) for a in resolvers if a.version == version]
        found = [
            str(n) for n in ipaddress.collapse_addresses(n for n in hosts if n.version == version)
        ]
        elements = [
            f"{_range_text(*span, version)} . {protocol} . {_port_text(*port_range)}"
            for span, protocol, port_range in _disjoint(hosts, ports, version)
        ]
        for name, items, set_kind in (
            (f"resolvers{version}", dns, kind),
            (f"hosts{version}", found, kind),
            (f"ports{version}", elements, f"{kind} . inet_proto . inet_service"),
        ):
            listed = f" elements = {{ {', '.join(items)} }};" if items else ""
            lines.append(f"  set {name} {{ type {set_kind}; flags interval;{listed} }}")
        lines.append(
            f"  set refused{version} {{ type {kind} . inet_proto . inet_service; "
            f"size {REFUSED_SET_SIZE}; flags dynamic; }}"
        )
    lines += [
        "  chain output {",
        "    type filter hook output priority filter + 10; policy accept;",
        f"    meta skuid {uid} jump restrict",
        "  }",
        "  chain restrict {",
        f"    ip daddr {_DOCKER_DNS} meta l4proto {{ tcp, udp }} ct original proto-dst 53 accept",
    ]
    for version, match, _ in versions:
        lines += [
            f"    {match} daddr @resolvers{version} meta l4proto {{ tcp, udp }} th dport 53 accept",
            f"    {match} daddr @hosts{version} accept",
            f"    {match} daddr . meta l4proto . th dport @ports{version} accept",
        ]
    for version, match, _ in versions:
        lines.append(
            f"    meta l4proto {{ tcp, udp }} add @refused{version} "
            f"{{ {match} daddr . meta l4proto . th dport }}"
        )
    other = "icmpx admin-prohibited" if ipv6 else "icmp admin-prohibited"
    lines += [
        "    meta l4proto tcp counter reject with tcp reset",
        f"    counter reject with {other}",
        "  }",
        "}",
    ]
    return "\n".join(lines) + "\n"


def release_ruleset(slots: Iterable[int], *, ipv6: bool = True) -> str:
    """Deletes these slots' tables, whether they exist or not."""
    family = "inet" if ipv6 else "ip"
    lines = []
    for slot in slots:
        lines += [
            f"add table {family} {slot_table(slot)}",
            f"delete table {family} {slot_table(slot)}",
        ]
    return "\n".join(lines) + "\n"


def parse_refused(text: str) -> list[dict]:
    """{"address", "protocol", "port"} for each element of `nft -j list set` output."""
    found = []
    try:
        data = json.loads(text)
    except ValueError:
        return found
    for item in data.get("nftables", []) if isinstance(data, dict) else []:
        for element in (item.get("set") or {}).get("elem") or [] if isinstance(item, dict) else []:
            value = (
                element.get("elem", {}).get("val")
                if isinstance(element, dict) and "elem" in element
                else element
            )
            parts = value.get("concat") if isinstance(value, dict) else None
            if not (isinstance(parts, list) and len(parts) == 3):
                continue
            address, protocol, port = parts
            try:
                address = str(ipaddress.ip_address(address))
                port = int(port)
            except (TypeError, ValueError):
                continue
            if protocol in _PROTOCOLS and 0 <= port <= 65535:
                found.append({"address": address, "protocol": protocol, "port": port})
    return found


def list_set(table: str, name: str, *, ipv6: bool = True) -> str:
    """`nft -j list set` output ("" if the set or table isn't there)."""
    nft = nft_path() or NFT_FALLBACK
    family = "inet" if ipv6 else "ip"
    try:
        result = run_child(
            [nft, "-j", "list", "set", family, table, name],
            timeout=_NFT_TIMEOUT_SECONDS,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EgressError(f"could not run nft: {exc}") from exc
    return result.stdout if result.returncode == 0 else ""


def nft_path() -> str | None:
    found = shutil.which("nft")
    if found is None and os.path.exists(NFT_FALLBACK):
        return NFT_FALLBACK
    return found


def check_available(status_path: str = "/proc/self/status") -> str | None:
    """None if this process can install the filter, else why not (for the log and the
    production refusal)."""
    if not sys.platform.startswith("linux"):
        return "the egress filter needs Linux"
    if os.geteuid() != 0:
        return 'the worker is not running as root (compose: user: "0")'
    try:
        with open(status_path, encoding="ascii") as status:
            caps = effective_caps(status.read())
    except OSError as exc:
        return f"could not read the worker's capabilities ({exc})"
    if not caps >> NET_ADMIN_BIT & 1:
        return "the worker lacks the NET_ADMIN capability (compose: cap_add)"
    if nft_path() is None:
        return "nft (nftables) is not installed"
    return None


def apply(script: str) -> None:
    nft = nft_path() or NFT_FALLBACK
    try:
        result = run_child(
            [nft, "-f", "-"],
            input_text=script,
            timeout=_NFT_TIMEOUT_SECONDS,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EgressError(f"could not run nft: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[-500:]
        raise EgressError(detail or f"nft exited with {result.returncode}")


def has_ipv6() -> bool:
    return os.path.exists("/proc/net/if_inet6")


def install(networks: list[Network]) -> None:
    """Installs the table; IPv4 only if the kernel has no IPv6."""
    try:
        apply(ruleset(networks))
    except EgressError:
        if has_ipv6():
            raise
        apply(ruleset(networks, ipv6=False))


def run_probe(command: list[str]) -> dict:
    """Runs the probe (as built by the caller, maybe wrapped as a slot user)."""
    try:
        result = run_child(command, timeout=30, env={"PATH": "/usr/bin:/bin"})
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EgressError(f"the egress probe could not run: {exc}") from exc
    if result.returncode != 0:
        raise EgressError(f"the egress probe failed: {result.stderr.strip()[-300:]}")
    return json.loads(result.stdout)


class EgressFilter:
    """The filter for one worker: start() installs it, refresh() follows the API's address."""

    def __init__(
        self,
        api_url: str,
        *,
        block_metadata: bool = True,
        extra: Iterable[Network] = (),
        resolver: Callable[[str, int], frozenset[Address]] = resolve,
        installer: Callable[[list[Network]], None] = install,
        prober: Callable[[list[str]], dict] = run_probe,
        applier: Callable[[str], None] = apply,
        lister: Callable[..., str] = list_set,
        ipv6: bool | None = None,
    ) -> None:
        self.host, self.port = api_endpoint(api_url)
        self.block_metadata = block_metadata
        self.static: list[Network] = [
            *(METADATA_NETWORKS if block_metadata else ()),
            *ALWAYS_BLOCKED,
            *extra,
        ]
        self.addresses: frozenset[Address] = frozenset()
        self.healthy = False
        # Whether restricted runs can be given allowlists here (set by test_allowlists()).
        self.allowlists_ready = False
        self.ipv6 = has_ipv6() if ipv6 is None else ipv6
        self._resolver, self._installer, self._prober = resolver, installer, prober
        self._applier, self._lister = applier, lister
        self._lock = threading.Lock()

    def networks(self) -> list[Network]:
        return [*self.static, *(ipaddress.ip_network(address) for address in self.addresses)]

    def start(self) -> None:
        """Installs the table with the API's addresses as far as they resolve yet (the
        static entries in any case). Raises EgressError."""
        with self._lock:
            try:
                self.addresses = self._resolver(self.host, self.port)
            except OSError as exc:
                logger.info("the API's address %s doesn't resolve yet (%s)", self.host, exc)
            self._install()
            # Allowlists an earlier worker left in this network namespace.
            self._applier(release_ruleset(range(MAX_SLOTS), ipv6=self.ipv6))

    def refresh(self) -> bool:
        """Looks the API up again and updates the table if its addresses changed (or the last
        update failed). Keeps the old ones while it doesn't resolve: Docker's DNS has no
        answer while the API's container is being recreated. Raises EgressError."""
        with self._lock:
            try:
                found = self._resolver(self.host, self.port)
            except OSError:
                return False
            if found == self.addresses and self.healthy:
                return False
            old, self.addresses = self.addresses, found
            self._install()
            if old and old != found:
                logger.info(
                    "the API's address changed (%s -> %s); egress filter updated",
                    _list(old),
                    _list(found),
                )
            return True

    def _install(self) -> None:
        self.healthy = False
        self._installer(self.networks())
        self.healthy = True

    def watch(self, stop: threading.Event) -> None:
        while not stop.wait(REFRESH_SECONDS):
            try:
                self.refresh()
            except EgressError as exc:
                logger.error("could not update the egress filter: %s", exc)

    def self_test(self, identities: Iterable[RunIdentity]) -> str | None:
        """None if each slot user is refused by the API (where the worker gets through), by
        the metadata address, and can still look names up; else what went wrong. Run it
        before any run: a run could interfere with a probe of its own slot."""
        if not self.addresses:
            return f"the API's address ({self.host}) doesn't resolve"
        targets = [(str(address), self.port) for address in sorted(self.addresses, key=str)]
        if self.block_metadata:
            targets.append(_METADATA_PROBE)
        try:
            for identity in identities:
                if reason := self._test_identity(identity, targets):
                    return reason
        except EgressError as exc:
            return str(exc)
        return None

    def _probe(self, targets: list[tuple[str, int]], identity: RunIdentity | None) -> dict:
        argument = json.dumps(
            {
                "name": None if _is_address(self.host) else self.host,
                "targets": targets,
                "timeout": _PROBE_TIMEOUT_SECONDS,
            }
        )
        command = [sys.executable, "-I", "-S", "-c", _PROBE, argument]
        return self._prober(command if identity is None else wrap(command, identity))

    def _test_identity(self, identity: RunIdentity, targets: list[tuple[str, int]]) -> str | None:
        api_targets = [t for t in targets if t != _METADATA_PROBE]
        for attempt in range(_PROBE_ATTEMPTS):
            before = self._probe(api_targets, None)["connect"]
            slot = self._probe(targets, identity)
            after = self._probe(api_targets, None)["connect"]
            for target, result in zip(targets, slot["connect"], strict=True):
                if result == "connected":
                    host, port = target
                    return f"{identity.name} could connect to {host} port {port}"
            if slot["resolved"] not in (None, "ok"):
                return f"{identity.name} can't look up names: {slot['resolved']}"
            if targets[-1] == _METADATA_PROBE and slot["connect"][-1] != "ECONNREFUSED":
                outcome = slot["connect"][-1]
                return f"{identity.name} wasn't refused by the metadata address ({outcome})"
            # Refused for the slot, where the worker got through just before and after.
            proven = any(
                b == a == "connected" and s == "ECONNREFUSED"
                for b, s, a in zip(before, slot["connect"], after, strict=False)
            )
            if proven:
                return None
            if attempt + 1 < _PROBE_ATTEMPTS:
                time.sleep(1)
        return (
            f"couldn't check the filter: the worker got {_list(before)} and {identity.name} "
            f"got {_list(slot['connect'])} connecting to the API"
        )

    def allow(self, identity: RunIdentity, allowlist: Allowlist) -> None:
        """Limits the slot's user to `allowlist` (plus DNS), until release(). Raises
        EgressError."""
        script = slot_ruleset(
            _slot_of(identity), identity.uid, allowlist, read_resolvers(), ipv6=self.ipv6
        )
        with self._lock:
            self._applier(script)

    def refused(self, identity: RunIdentity) -> list[dict]:
        """The destinations the slot's user was refused (the first REFUSED_SET_SIZE)."""
        table = slot_table(_slot_of(identity))
        found: list[dict] = []
        for version in (4, 6) if self.ipv6 else (4,):
            found += parse_refused(self._lister(table, f"refused{version}", ipv6=self.ipv6))
        return found

    def release(self, identity: RunIdentity) -> None:
        """Lifts the slot's allowlist (whether it has one or not). Raises EgressError."""
        with self._lock:
            self._applier(release_ruleset([_slot_of(identity)], ipv6=self.ipv6))

    def test_allowlists(self, identity: RunIdentity) -> str | None:
        """None if an allowlist works for this slot user: an allowed port is reached, another
        refused and recorded, the API stays refused although allowed (the blocklist wins),
        names still resolve, a host is reached on any port, and release() lifts it all; else
        what went wrong. Needs no outside host: the worker listens on two loopback ports.
        Run it before any run, like self_test()."""
        if not self.addresses:
            return f"the API's address ({self.host}) doesn't resolve"
        loopback = ipaddress.ip_network("127.0.0.1/32")
        api = [(str(address), self.port) for address in sorted(self.addresses, key=str)]
        with (
            socket.create_server(("127.0.0.1", 0)) as one,
            socket.create_server(("127.0.0.1", 0)) as two,
        ):
            open_port, closed_port = one.getsockname()[1], two.getsockname()[1]
            targets = [("127.0.0.1", open_port), ("127.0.0.1", closed_port), *api]
            try:
                self.allow(identity, Allowlist(
                    hosts=tuple(ipaddress.ip_network(a) for a in self.addresses),
                    ports=((loopback, "tcp", open_port, open_port),),
                ))  # fmt: skip
                slot = self._probe(targets, identity)
                expected = ["connected", "ECONNREFUSED"] + ["ECONNREFUSED"] * len(api)
                if slot["connect"] != expected:
                    return (
                        f"an allowlist didn't work for {identity.name}: got "
                        f"{', '.join(slot['connect'])} where {', '.join(expected)} was expected"
                    )
                if slot["resolved"] not in (None, "ok"):
                    problem = slot["resolved"]
                    return f"{identity.name} can't look up names under an allowlist: {problem}"
                wanted = {"address": "127.0.0.1", "protocol": "tcp", "port": closed_port}
                if wanted not in self.refused(identity):
                    return f"a connection {identity.name} was refused wasn't recorded"
                self.allow(identity, Allowlist(hosts=(loopback,)))
                if self._probe(targets[1:2], identity)["connect"] != ["connected"]:
                    return f"an allowlisted host wasn't reachable on every port for {identity.name}"
                self.release(identity)
                if self._probe(targets[1:2], identity)["connect"] != ["connected"]:
                    return f"releasing {identity.name}'s allowlist didn't lift it"
            except EgressError as exc:
                return str(exc)
            finally:
                with contextlib.suppress(EgressError):
                    self.release(identity)
        return None

    def describe(self) -> str:
        allowlists = ", allowlists" if self.allowlists_ready else ""
        return f"egress filtered (API {_list(self.addresses) or self.host}){allowlists}"


def _is_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _list(items: Iterable[object]) -> str:
    return ", ".join(sorted(map(str, items)))
