"""Keeps runs away from the API and cloud metadata (the worker's egress filter).

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

Imports only the standard library, app.run_isolation and app.run_executor (see app.worker).
"""

import ipaddress
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


def install(networks: list[Network]) -> None:
    """Installs the table; IPv4 only if the kernel has no IPv6."""
    try:
        apply(ruleset(networks))
    except EgressError:
        if os.path.exists("/proc/net/if_inet6"):
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
        self._resolver, self._installer, self._prober = resolver, installer, prober
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

    def describe(self) -> str:
        return f"egress filtered (API {_list(self.addresses) or self.host})"


def _is_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _list(items: Iterable[object]) -> str:
    return ", ".join(sorted(map(str, items)))
