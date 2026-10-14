"""SSH host keys for runs: per-inventory known_hosts that ssh checks the targets against.

An inventory's mode says how a run treats host keys:
- "off": as before (ansible-runner turns host key checking off);
- "accept_new": known keys are checked, a host without one is learned on first contact
  (ssh's StrictHostKeyChecking=accept-new) and reported back;
- "strict": only confirmed keys (scanned, pasted, or learned and then confirmed) are trusted.

A key is stored under the name ssh looks it up by: the address it connects to, lowercased,
with the port in brackets when it isn't 22 (`web1`, `[10.0.0.5]:2222`). This module is pure
(the worker imports it too); app.host_key_store keeps the keys.
"""

import base64
import binascii
import contextlib
import hashlib
import re
import struct
from dataclasses import dataclass

MODES = ("off", "accept_new", "strict")
DEFAULT_MODE = "accept_new"  # new inventories; existing ones were migrated to "off"

# Plain host keys only: no certificates, no DSA (gone from OpenSSH 10).
KEY_TYPES = frozenset(
    {
        "ssh-ed25519",
        "ssh-rsa",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "sk-ssh-ed25519@openssh.com",
        "sk-ecdsa-sha2-nistp256@openssh.com",
    }
)
MAX_KEY_BYTES = 16 * 1024
MAX_NAME = 300
MAX_PASTED_LINES = 2000
MAX_LEARNED_LINES = 200  # a run reports at most this many learned keys
MAX_PROBLEMS = 100  # and this many refused hosts
# What a known_hosts name may hold: a host name or IPv4/IPv6 address, bracketed with a port.
_HOST = r"[a-z0-9_][a-z0-9_.:%-]*"
_NAME = re.compile(rf"^(?:{_HOST}|\[{_HOST}\]:\d{{1,5}})$")
_TEMPLATE = ("{{", "{%", "{#")


@dataclass(frozen=True)
class KnownHost:
    name: str
    key_type: str
    key_b64: str
    fingerprint: str

    @property
    def line(self) -> str:
        return f"{self.name} {self.key_type} {self.key_b64}"


def fingerprint(key_b64: str) -> str:
    """The key's SHA256 fingerprint, as `ssh-keygen -l` shows it."""
    digest = hashlib.sha256(base64.b64decode(key_b64)).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def alias(host: str, port: int | None = None) -> str:
    """The known_hosts name ssh looks a host up by."""
    host = host.lower()
    return host if port in (None, 22) else f"[{host}]:{port}"


def normalise_name(name: str) -> str | None:
    """A known_hosts name as stored, or None if it isn't one plain name (wildcards, negations,
    hashed names and markers are refused: each key belongs to exactly one address)."""
    name = name.strip().lower()
    if not name or len(name) > MAX_NAME or not _NAME.fullmatch(name):
        return None
    if name.startswith("["):
        port = int(name.rsplit(":", 1)[1])
        if not 1 <= port <= 65535:
            return None
        if port == 22:  # ssh looks port 22 up without brackets
            return name[1:].rsplit("]:", 1)[0]
    return name


def check_key(key_type: str, key_b64: str) -> str:
    """The key's fingerprint; ValueError unless it is a plain host key of a known type whose
    blob says the same type."""
    if key_type not in KEY_TYPES:
        raise ValueError(f"unsupported key type {key_type[:60]!r}")
    if len(key_b64) > MAX_KEY_BYTES * 4 // 3 + 4:
        raise ValueError("the key is too long")
    try:
        blob = base64.b64decode(key_b64, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("the key is not valid base64") from None
    if len(blob) < 4:
        raise ValueError("the key is too short")
    (length,) = struct.unpack(">I", blob[:4])
    if blob[4 : 4 + length] != key_type.encode():
        raise ValueError(f"the key's data isn't a {key_type} key")
    return fingerprint(key_b64)


def parse_known_hosts(
    text: str, max_lines: int = MAX_PASTED_LINES
) -> tuple[list[KnownHost], list[str]]:
    """Known_hosts text as (keys, warnings about the lines left out). A line naming several
    hosts (`web1,10.0.0.5 ssh-ed25519 AAAA...`) gives one key per name."""
    keys: dict[tuple[str, str], KnownHost] = {}
    warnings: list[str] = []
    lines = text.splitlines()
    if len(lines) > max_lines:
        warnings.append(f"only the first {max_lines} lines were read")
    for number, raw in enumerate(lines[:max_lines], start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("@"):
            warnings.append(f"line {number}: @cert-authority and @revoked lines aren't supported")
            continue
        parts = line.split()
        if len(parts) < 3:
            warnings.append(f"line {number}: not a known_hosts line")
            continue
        names, key_type, key_b64 = parts[0], parts[1], parts[2]
        try:
            found = check_key(key_type, key_b64)
        except ValueError as exc:
            warnings.append(f"line {number}: {exc}")
            continue
        for raw_name in names.split(","):
            name = normalise_name(raw_name)
            if name is None:
                shown = raw_name[:60] + ("…" if len(raw_name) > 60 else "")
                why = "hashed names" if raw_name.startswith("|") else f"{shown!r}"
                warnings.append(f"line {number}: {why} can't be used (one plain name per key)")
                continue
            keys[(name, key_type)] = KnownHost(name, key_type, key_b64, found)
    return list(keys.values()), warnings


@dataclass(frozen=True)
class HostAddress:
    """Where a run connects to an inventory host, as far as the inventory says. `name` is None
    when it can't be known in advance (a templated address or port); `checked` is False for
    hosts not reached over ssh."""

    name: str | None
    connection: str
    checked: bool
    reason: str | None = None


# Connection plugins that run ssh itself; the rest (local, winrm, network_cli/paramiko, ...)
# don't use the managed known_hosts.
SSH_CONNECTIONS = frozenset({"ssh", "smart"})


def _templated(value) -> bool:
    return isinstance(value, str) and any(mark in value for mark in _TEMPLATE)


def _port(value) -> int | None:
    if isinstance(value, bool):
        raise ValueError
    if isinstance(value, int):
        port = value
    elif isinstance(value, str) and value.strip().isdigit():
        port = int(value.strip())
    else:
        raise ValueError
    if not 1 <= port <= 65535:
        raise ValueError
    return port


def address_of(inventory_hostname: str, host_vars: dict) -> HostAddress:
    """ssh's connection options take the last of their variables that is set: ansible_ssh_host
    over ansible_host over the inventory name, ansible_ssh_port over ansible_port."""
    connection = host_vars.get("ansible_connection") or "ssh"
    if _templated(connection) or not isinstance(connection, str):
        return HostAddress(None, "?", False, "its connection is set by a template")
    if connection not in SSH_CONNECTIONS:
        return HostAddress(None, connection, False, f"connects with {connection}, not ssh")
    host = inventory_hostname
    for var in ("ansible_host", "ansible_ssh_host"):
        if host_vars.get(var) not in (None, ""):
            host = host_vars[var]
    port = None
    for var in ("ansible_port", "ansible_ssh_port"):
        if host_vars.get(var) not in (None, ""):
            port = host_vars[var]
    if _templated(host) or _templated(port):
        return HostAddress(None, "ssh", True, "its address is set by a template")
    try:
        port = _port(port) if port is not None else None
    except ValueError:
        return HostAddress(None, "ssh", True, "its port isn't a number")
    name = normalise_name(alias(str(host), port)) if isinstance(host, str) else None
    if name is None:
        return HostAddress(None, "ssh", True, "its address isn't a plain host name")
    return HostAddress(name, "ssh", True)


def host_addresses(graph: dict) -> dict[str, HostAddress]:
    """Every host of a merged inventory (app.inventory_render.merge) with its address. Group
    and host vars are combined by ansible's own rules (child groups over parents, host vars
    over group vars); nothing is templated. Vars from a repository's group_vars/host_vars
    aren't seen here."""
    from ansible.errors import AnsibleError
    from ansible.inventory.data import InventoryData
    from ansible.inventory.helpers import get_group_vars
    from ansible.utils.vars import combine_vars

    data = InventoryData()
    for name, value in (graph.get("vars") or {}).items():
        data.set_variable("all", name, value)
    for group_name in graph["groups"]:
        if group_name not in ("all", "ungrouped"):
            data.add_group(group_name)
    for host_name, host_vars in graph["hosts"].items():
        data.add_host(host_name)
        for name, value in (host_vars or {}).items():
            data.set_variable(host_name, name, value)
    for group_name, group in graph["groups"].items():
        for name, value in (group.get("vars") or {}).items():
            data.set_variable(group_name, name, value)
        for child in group.get("children") or ():
            if child in data.groups and child != group_name:
                with contextlib.suppress(AnsibleError):  # a cycle: ansible refuses it too
                    data.add_child(group_name, child)
        for host_name in group.get("hosts") or ():
            if host_name in data.hosts:
                data.add_child(group_name, host_name)
    data.reconcile_inventory()
    result = {}
    for host_name, host in data.hosts.items():
        merged = combine_vars(get_group_vars(host.get_groups()), host.get_vars())
        result[host_name] = address_of(host_name, merged)
    return result


# What ssh says when it refuses a host key (OpenSSH 8-10), in ansible's unreachable message.
_CHANGED = re.compile(r"Host key for (\S+) has changed and you have requested strict checking")
_UNKNOWN = re.compile(r"No (\S+) host key is known for (\S+) and you have requested strict")
_PRESENTED = re.compile(
    r"The fingerprint for the (\S+) key sent by the remote host is\s+(SHA256:[A-Za-z0-9+/]{43})"
)
_FAILED = "Host key verification failed"
_SAFE = re.compile(r"[^A-Za-z0-9_.:%\[\]@-]")


def _safe(text: str, limit: int = MAX_NAME) -> str:
    return _SAFE.sub("", text)[:limit]


def host_key_problem(event: dict) -> dict | None:
    """{"host", "problem": changed|unknown|failed, "name", "key_type", "presented"} for an
    unreachable event caused by a refused host key, else None. Event data is untrusted (the
    playbook's process writes it): everything kept is cut to safe characters."""
    if event.get("event") != "runner_on_unreachable":
        return None
    data = event.get("event_data") or {}
    result = data.get("res") if isinstance(data.get("res"), dict) else {}
    message = result.get("msg")
    if not isinstance(message, str) or _FAILED not in message:
        return None
    problem = {
        "host": _safe(str(data.get("host") or "?"), 255),
        "problem": "failed",
        "name": None,
        "key_type": None,
        "presented": None,
    }
    if changed := _CHANGED.search(message):
        problem.update(problem="changed", name=_safe(changed.group(1)))
        if presented := _PRESENTED.search(message):
            problem.update(key_type=_safe(presented.group(1), 20), presented=presented.group(2))
    elif unknown := _UNKNOWN.search(message):
        problem.update(
            problem="unknown", key_type=_safe(unknown.group(1), 20), name=_safe(unknown.group(2))
        )
    return problem
