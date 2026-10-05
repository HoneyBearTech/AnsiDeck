"""The inventory a run sees: the inventory's own (static) hosts and groups, merged with its
sources' latest snapshot (Phase 4G), rendered as ansible's YAML inventory with the whole
group tree, so a play's `hosts: web` matches whichever group is called web.

Static data wins: a static host's vars override a source's per top-level key, and static group
membership is the inventory's own. Strings that came from a source are rendered `!unsafe`:
a template in NetBox or cloud data (`{{ lookup('pipe', ...) }}`) is never evaluated in a run.
Static strings stay templatable, as before.
"""

import copy
import re
from typing import Any

import yaml
from ansible.parsing.utils.addresses import parse_address
from ansible.plugins.inventory import detect_range

from app.models import Inventory

MAX_NAME = 255
RESERVED_GROUPS = frozenset({"all", "ungrouped"})
# Ansible itself only warns about '-' and '.' in group names; braces, spaces, ':' or ','
# would break host patterns (`hosts:`, --limit).
GROUP_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$")
HOSTNAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.:%-]*$")


def hostname_problem(name: object) -> str | None:
    """Why ansible wouldn't see exactly this one host, or None. The YAML inventory re-parses
    host keys: 'db:5432' becomes db with a port and 'web[1:3]' three hosts."""
    if not isinstance(name, str) or not name or len(name) > MAX_NAME:
        return "must be 1-255 characters"
    if not HOSTNAME.fullmatch(name):
        return "may hold only letters, digits and . _ - : %"
    try:
        pattern, port = parse_address(name, allow_ranges=True)
    except Exception:  # noqa: BLE001 - not an address: ansible takes it as the name itself
        pattern, port = name, None
    if port is not None:
        return "must not include a port (set ansible_port instead)"
    if pattern != name or detect_range(pattern):
        return "would not be read as a single host name"
    return None


def group_problem(name: object) -> str | None:
    if not isinstance(name, str) or not name or len(name) > MAX_NAME:
        return "must be 1-255 characters"
    if name in RESERVED_GROUPS:
        return f"'{name}' is reserved by ansible"
    if not GROUP_NAME.fullmatch(name):
        return "may hold only letters, digits and . _ - (not starting with . or -)"
    return None


class Unsafe(str):
    """A string from a source: rendered `!unsafe`, never templated."""


def mark_unsafe(value: Any) -> Any:
    if isinstance(value, str):
        return Unsafe(value)
    if isinstance(value, dict):
        return {mark_unsafe(k): mark_unsafe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [mark_unsafe(v) for v in value]
    return value


class _Dumper(yaml.SafeDumper):
    pass


_RESOLVER = yaml.resolver.Resolver()
_STR_TAG = "tag:yaml.org,2002:str"


def _represent_unsafe(dumper: yaml.SafeDumper, data: Unsafe) -> yaml.ScalarNode:
    # Ansible's !unsafe re-resolves the scalar ignoring its quotes: '1', 'true', '~' or ''
    # would come back as a number, a bool or None. Those can't hold a template ('{' or a
    # '#jinja2:' header), so they are written as ordinary quoted strings.
    if _RESOLVER.resolve(yaml.ScalarNode, data, (True, False)) != _STR_TAG:
        return dumper.represent_str(str(data))
    return dumper.represent_scalar("!unsafe", str(data))


_Dumper.add_representer(Unsafe, _represent_unsafe)


def static_data(inventory: Inventory) -> dict:
    """The inventory's own hosts and groups, as a run pins them when it is triggered."""
    return {
        "hosts": {host.hostname: copy.deepcopy(host.vars or {}) for host in inventory.hosts},
        "groups": {
            group.name: [host.hostname for host in group.hosts] for group in inventory.groups
        },
    }


def static_problems(static: dict) -> list[str]:
    """Names in an inventory's own data that can't be rendered faithfully (rows from before
    names were checked)."""
    problems = [
        f"host '{name}' {problem}"
        for name in static["hosts"]
        if (problem := hostname_problem(name))
    ]
    problems += [
        f"group '{name}' {problem}" for name in static["groups"] if (problem := group_problem(name))
    ]
    return problems


def merge(static: dict, snapshot: dict | None = None) -> dict:
    """{"vars", "hosts": {name: vars}, "groups": {name: {"hosts", "children", "vars"}}}.

    `snapshot`: a source refresh's normalised output, with `static_hosts` (the inventory's
    own hosts as fed to the plugins). Those that are gone now are dropped; for those still
    here, membership of the inventory's own groups comes from the static data alone."""
    hosts: dict[str, dict] = {}
    groups: dict[str, dict] = {}
    all_vars: dict = {}
    static_hosts = static["hosts"]
    if snapshot is not None:
        was_static = set(snapshot.get("static_hosts") or ())
        gone = was_static - static_hosts.keys()
        all_vars = mark_unsafe(snapshot.get("vars") or {})
        for name, host_vars in snapshot["hosts"].items():
            if name not in gone:
                hosts[name] = mark_unsafe(host_vars or {})
        for name, group in snapshot["groups"].items():
            skip = gone | (was_static if name in static["groups"] else set())
            groups[name] = {
                "hosts": {h: None for h in group.get("hosts") or () if h not in skip},
                "children": list(group.get("children") or ()),
                "vars": mark_unsafe(group.get("vars") or {}),
            }
    for name, host_vars in static_hosts.items():
        merged = hosts.get(name, {})
        merged.update(copy.deepcopy(host_vars or {}))
        hosts[name] = merged
    for name, members in static["groups"].items():
        group = groups.setdefault(name, {"hosts": {}, "children": [], "vars": {}})
        group["hosts"].update(dict.fromkeys(members))
    for group in groups.values():
        group["hosts"] = list(group["hosts"])
    return {"vars": all_vars, "hosts": hosts, "groups": groups}


def target_hosts(graph: dict, group: str) -> set[str]:
    """The hosts in a group or any group below it (what `--limit group` selects)."""
    if group not in graph["groups"]:
        raise KeyError(group)
    found: set[str] = set()
    seen: set[str] = set()
    pending = [group]
    while pending:
        name = pending.pop()
        if name in seen or name not in graph["groups"]:
            continue
        seen.add(name)
        found.update(graph["groups"][name]["hosts"])
        pending.extend(graph["groups"][name]["children"])
    return found


def render(graph: dict, target: str | None = None) -> str:
    """Ansible YAML inventory for a run; with a target group, every group stays (its vars
    and name still resolve) but holds only that group's hosts."""
    keep = target_hosts(graph, target) if target is not None else None

    def wanted(host: str) -> bool:
        return keep is None or host in keep

    block: dict = {}
    if graph["vars"]:
        block["vars"] = graph["vars"]
    host_block = {h: (v or None) for h, v in graph["hosts"].items() if wanted(h)}
    if host_block:
        block["hosts"] = host_block
    children: dict = {}
    for name, group in graph["groups"].items():
        entry: dict = {}
        members = {h: None for h in group["hosts"] if wanted(h)}
        if members:
            entry["hosts"] = members
        if group["children"]:
            entry["children"] = dict.fromkeys(group["children"])
        if group["vars"]:
            entry["vars"] = group["vars"]
        children[name] = entry or None
    if children:
        block["children"] = children
    return yaml.dump({"all": block or None}, Dumper=_Dumper, sort_keys=False)


def all_vars_dicts(graph: dict) -> list[dict]:
    """Every vars mapping in a merged inventory (for collecting secrets to scrub)."""
    return [
        graph["vars"],
        *graph["hosts"].values(),
        *(group["vars"] for group in graph["groups"].values()),
    ]
