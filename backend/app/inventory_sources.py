"""Dynamic inventory sources (Phase 4G): an inventory plugin's config, run by ansible-inventory
in an isolated worker when the inventory is refreshed. The output is untrusted (plugins are
third-party code, their data comes from outside), so the API checks and normalises it here
and stores it as a snapshot; runs pin the current snapshot when they are triggered and
app.inventory_render merges it with the inventory's own hosts (static wins, strings from a
source are never templated).

A refresh feeds ansible-inventory, in this order: every enabled source but `constructed`
ones, then the inventory's own hosts and groups, then the `constructed` sources (so they can
group static and dynamic hosts by their vars).
"""

import hashlib
import json
import logging
import re
from typing import Any

import yaml
from sqlalchemy import exists, func, select, text, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.config import get_settings
from app.env_credentials import env_problem, resolve_env
from app.inventory_render import (
    group_problem,
    hostname_problem,
    mark_unsafe,
    merge,
    render,
    source_var_problem,
    static_data,
)
from app.json_limits import TooDeep, loads_bounded
from app.models import (
    Credential,
    Inventory,
    InventoryRefresh,
    InventoryRefreshSource,
    InventorySnapshot,
    InventorySource,
    InventorySourceOutput,
    Run,
    RunStatus,
)
from app.scrub import is_secret_key
from app.secret_store import SecretStoreError, new_deadline

logger = logging.getLogger(__name__)

MAX_CONFIG_BYTES = 64 * 1024
MAX_VARS_DEPTH = 32
MAX_EDGES = 200_000
KEEP_SNAPSHOTS = 5
TRIGGERS = ("manual", "schedule", "sources_changed", "static_changed", "run")
PLUGIN_NAME = re.compile(r"[a-z0-9_]+(\.[a-z0-9_]+\.[a-z0-9_]+)?")
# Plugins that read files or run executables by path rather than a config: a source is a
# plugin config. `auto` would load itself forever.
_DENIED = frozenset({"auto", "script", "host_list", "advanced_host_list", "ini", "yaml", "toml"})
# Most plugins accept a config file ending in "<their short name>.yml"; these want another.
_SUFFIX_OVERRIDES = {"google.cloud.gcp_compute": "gcp"}
_CONSTRUCTED = frozenset({"constructed", "ansible.builtin.constructed"})
# One shown per kind of problem; a refresh's warnings stay short.
_MAX_WARNINGS = 20


class SourceError(ValueError):
    """A config or a refresh's output that can't be used (the message is safe to show)."""


# --- configs ----------------------------------------------------------------------------


def check_config(config: str) -> str:
    """The config's plugin name, or SourceError saying what is wrong with it."""
    if len(config.encode()) > MAX_CONFIG_BYTES:
        raise SourceError(f"the config is larger than {MAX_CONFIG_BYTES // 1024} KiB")
    try:
        data = yaml.safe_load(config)
    except yaml.YAMLError as exc:
        raise SourceError(f"the config is not valid YAML: {str(exc)[:200]}") from None
    if not isinstance(data, dict):
        raise SourceError("the config must be a YAML mapping with a 'plugin' key")
    plugin = data.get("plugin")
    if not isinstance(plugin, str) or not PLUGIN_NAME.fullmatch(plugin):
        raise SourceError("'plugin' must name an inventory plugin, e.g. netbox.netbox.nb_inventory")
    short = plugin.removeprefix("ansible.builtin.").removeprefix("ansible.legacy.")
    if plugin in _DENIED or short in _DENIED:
        raise SourceError(f"the {plugin} plugin can't be used as a source")
    if data.get("cache"):
        raise SourceError("'cache' must be off: AnsiDeck keeps each refresh as a snapshot")
    if secret := _literal_secret(data):
        raise SourceError(
            f"'{secret}' holds a literal value: put secrets in an environment-variable "
            "credential (the config is shown to anyone who can see the inventory)"
        )
    return plugin


def _literal_secret(value: Any, depth: int = 0) -> str | None:
    """A secret-looking key with a literal (non-templated) value, if any."""
    if depth > MAX_VARS_DEPTH:
        return None
    if isinstance(value, dict):
        for key, item in value.items():
            if (
                isinstance(key, str)
                and key.lower() != "key"  # constructed's keyed_groups: an expression
                and is_secret_key(key)
                and isinstance(item, str)
                and item
                and "{{" not in item
            ):
                return key
            if found := _literal_secret(item, depth + 1):
                return found
    elif isinstance(value, list):
        for item in value:
            if found := _literal_secret(item, depth + 1):
                return found
    return None


def is_constructed(source: InventorySource) -> bool:
    return source.plugin in _CONSTRUCTED


def config_file_name(source: InventorySource, order: int) -> str:
    suffix = _SUFFIX_OVERRIDES.get(source.plugin, source.plugin.rsplit(".", 1)[-1])
    return f"{order:02d}-src{source.id}.{suffix}.yml"


def ordered_sources(inventory: Inventory) -> list[InventorySource]:
    """The enabled sources in the order ansible-inventory reads them (constructed last)."""
    enabled = [s for s in inventory.sources if s.enabled]
    return [s for s in enabled if not is_constructed(s)] + [s for s in enabled if is_constructed(s)]


# --- queueing ---------------------------------------------------------------------------


def has_sources(db: Session, inventory_id: int) -> bool:
    return bool(
        db.scalar(
            select(
                exists().where(
                    InventorySource.inventory_id == inventory_id, InventorySource.enabled
                )
            )
        )
    )


def enqueue_refresh(
    db: Session,
    inventory: Inventory,
    trigger: str,
    requested_by: str | None = None,
    source_ids: list[int] | None = None,
) -> int | None:
    """Queues a refresh of `source_ids` (None: every source; []: none, only combining what the
    sources found last with the inventory's own hosts and constructed sources). The caller
    commits and wakes the workers. A request while one is already queued merges into it,
    widening what it runs: returns None then, or when there is nothing to refresh."""
    if not has_sources(db, inventory.id):
        return None
    scope = None if source_ids is None else sorted(set(source_ids))
    stmt = (
        insert(InventoryRefresh)
        .values(
            inventory_id=inventory.id,
            project_id=inventory.project_id,
            status=RunStatus.QUEUED.value,
            trigger=trigger,
            requested_by=requested_by,
            timeout_seconds=get_settings().inventory_refresh_timeout_seconds,
            scope=scope,
        )
        .on_conflict_do_nothing(
            index_elements=[InventoryRefresh.inventory_id],
            index_where=text("status = 'queued'"),
        )
        .returning(InventoryRefresh.id)
    )
    refresh_id = db.scalar(stmt)
    if refresh_id is None:
        queued = db.scalars(
            select(InventoryRefresh)
            .where(
                InventoryRefresh.inventory_id == inventory.id,
                InventoryRefresh.status == RunStatus.QUEUED.value,
            )
            .with_for_update()
        ).first()
        if queued is None:  # claimed in between: queue a new one after all
            refresh_id = db.scalar(stmt)
        elif queued.scope is not None:
            queued.scope = None if scope is None else sorted(set(queued.scope) | set(scope))
    db.execute(
        update(InventorySource)
        .where(
            InventorySource.inventory_id == inventory.id,
            InventorySource.id.in_(scope) if scope is not None else InventorySource.enabled,
        )
        .values(last_queued_at=func.now())
    )
    return refresh_id


def effective_interval(source: InventorySource, inventory: Inventory) -> int:
    """How often a schedule refreshes the source (0: only when something changes)."""
    if is_constructed(source):
        return 0  # re-applied in every refresh, never run on its own
    if source.refresh_interval_seconds is not None:
        return source.refresh_interval_seconds
    return inventory.refresh_interval_seconds


def due_sources(db: Session) -> dict[int, list[int]]:
    """The sources whose interval (their own, or their inventory's) has passed since a refresh
    was last queued to run them, by inventory."""
    interval = func.coalesce(
        InventorySource.refresh_interval_seconds, Inventory.refresh_interval_seconds
    )
    rows = db.execute(
        select(InventorySource.inventory_id, InventorySource.id, InventorySource.plugin)
        .join(Inventory, Inventory.id == InventorySource.inventory_id)
        .where(
            InventorySource.enabled,
            interval > 0,
            InventorySource.last_queued_at.is_(None)
            | (
                InventorySource.last_queued_at + func.make_interval(0, 0, 0, 0, 0, 0, interval)
                <= func.now()
            ),
        )
        .order_by(InventorySource.inventory_id, InventorySource.id)
    )
    due: dict[int, list[int]] = {}
    for inventory_id, source_id, plugin in rows:
        if plugin not in _CONSTRUCTED:
            due.setdefault(inventory_id, []).append(source_id)
    return due


# --- the job ------------------------------------------------------------------------------


def input_sha256(source: InventorySource) -> str:
    """What a source's output depends on (its plugin config and credential): an output made
    from anything else is stale."""
    material = json.dumps([source.plugin, source.config, source.credential_id])
    return hashlib.sha256(material.encode()).hexdigest()


def _source_env(
    db: Session, inventory: Inventory, source: InventorySource, deadline: float
) -> dict[str, str]:
    """The variables of the source's credential ({} without one)."""
    if source.credential_id is None:
        return {}
    credential = db.get(Credential, source.credential_id)
    if credential is None or credential.project_id != inventory.project_id:
        raise RuntimeError(f"source {source.id}: its credential is not in its project")
    if credential.kind != "env":
        raise SourceError(f"source '{source.name}': its credential is not env variables")
    try:
        values = resolve_env(credential, deadline)
    except SecretStoreError as exc:
        exc.subject = f"credential '{credential.name}'"
        raise
    if problem := env_problem(values):  # a name denied since the credential was saved
        raise SourceError(f"credential '{credential.name}': {problem}")
    return values


def build_refresh_job(db: Session, refresh: InventoryRefresh) -> dict:
    """Stage one of a refresh: one ansible-inventory call per source (constructed ones wait for
    the combine), each with its own config and only its own credential's variables. Records
    what each source is to do. SecretStoreError (with `.subject`) when a credential in the
    secret store can't be read."""
    inventory = db.get(Inventory, refresh.inventory_id)
    if inventory is None or inventory.project_id != refresh.project_id:
        raise RuntimeError(f"refresh {refresh.id}: its inventory is gone or moved")
    sources = ordered_sources(inventory)
    if not sources:
        raise SourceError("the inventory has no enabled sources")
    deadline = new_deadline()
    calls: list[dict] = []
    secrets: set[str] = set()
    scope = None if refresh.scope is None else set(refresh.scope)
    for source in sources:
        # Constructed sources run in the combine; the others when this refresh is for them,
        # or when nothing ran them since they were added or changed.
        runs = not is_constructed(source) and (
            scope is None or source.id in scope or source.last_queued_at is None
        )
        db.add(
            InventoryRefreshSource(
                refresh_id=refresh.id,
                source_id=source.id,
                name=source.name,
                plugin=source.plugin,
                ran=runs,
                input_sha256=input_sha256(source),
            )
        )
        if not runs:
            continue
        source.last_queued_at = func.now()
        env = _source_env(db, inventory, source, deadline)
        secrets.update(env.values())
        calls.append(
            {
                "key": f"s{source.id}",
                "kind": "plugin",
                "files": [{"name": config_file_name(source, 10), "text": source.config}],
                "env": env,
            }
        )
    static = static_data(inventory)
    refresh.stage = "sources"
    refresh.sources = {
        "sources": [
            {
                "id": s.id,
                "name": s.name,
                "plugin": s.plugin,
                "sha256": hashlib.sha256(s.config.encode()).hexdigest(),
            }
            for s in sources
        ],
        "static_hosts": list(static["hosts"]),
    }
    return {
        "kind": "refresh",
        "calls": calls,
        "secrets": sorted(secrets),
        "timeout_seconds": refresh.timeout_seconds,
        "max_output_bytes": get_settings().inventory_max_output_mb * 1024 * 1024,
    }


# --- the output ---------------------------------------------------------------------------


class _Vaulted(Exception):
    pass


def _unwrap(value: Any, depth: int = 0) -> Any:
    """ansible-inventory's legacy JSON as plain data: untrusted strings come as
    {"__ansible_unsafe": str} (every source string is untrusted to AnsiDeck anyway)."""
    if depth > MAX_VARS_DEPTH:
        raise SourceError(f"a value is nested deeper than {MAX_VARS_DEPTH} levels")
    if isinstance(value, dict):
        if "__ansible_vault" in value:
            raise _Vaulted
        if len(value) == 1 and "__ansible_unsafe" in value:
            inner = value["__ansible_unsafe"]
            if not isinstance(inner, str):
                raise SourceError("unexpected output from ansible-inventory")
            return inner
        return {str(k): _unwrap(v, depth + 1) for k, v in value.items()}
    if isinstance(value, list):
        return [_unwrap(v, depth + 1) for v in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise SourceError("unexpected output from ansible-inventory")


def _parse_vars(value: Any, where: str, warnings: list[str]) -> dict:
    """A source's vars as plain data, minus vault values (the Ansible settings are still in:
    constructed sources may group by them; filter_graph drops them)."""
    if not isinstance(value, dict):
        raise SourceError(f"{where}: vars must be a mapping")
    out = {}
    for key, item in value.items():
        try:
            out[str(key)] = _unwrap(item, 1)
        except _Vaulted:
            _warn(warnings, f"{where}: dropped {key}, a vault-encrypted value")
    return out


def _filter_vars(value: dict, where: str, warnings: list[str], quiet: bool = False) -> dict:
    """Without the Ansible settings sources may not set. `quiet`: a static host's echo of its
    own vars (they win in merge anyway), so dropping its connection settings is no news."""
    out = {}
    for key, item in value.items():
        if problem := source_var_problem(key, item):
            if not quiet:
                _warn(warnings, f"{where}: dropped {key[:100]}: it {problem}")
            continue
        out[key] = item
    return out


def _warn(warnings: list[str], message: str) -> None:
    if len(warnings) < _MAX_WARNINGS:
        warnings.append(message[:300])
    elif len(warnings) == _MAX_WARNINGS:
        warnings.append("… more warnings not shown")


def parse_output(raw: bytes) -> tuple[dict, list[str]]:
    """ansible-inventory --list --export output as {"vars", "hosts", "groups"} plus warnings, or
    SourceError. Names ansible would read differently are skipped with a warning; vault values
    are dropped; anything over the limits fails. Ansible settings in vars are kept."""
    settings = get_settings()
    if len(raw) > settings.inventory_max_output_mb * 1024 * 1024:
        raise SourceError(f"the output is larger than {settings.inventory_max_output_mb} MiB")
    try:
        # The output's own structure (_meta, hostvars, a host) wraps the vars.
        data = loads_bounded(raw, MAX_VARS_DEPTH + 8)
    except TooDeep:
        raise SourceError(f"a value is nested deeper than {MAX_VARS_DEPTH} levels") from None
    except (ValueError, RecursionError):
        raise SourceError("the output is not valid JSON") from None
    if not isinstance(data, dict) or not isinstance(data.get("_meta", {}), dict):
        raise SourceError("unexpected output from ansible-inventory")
    meta = data.pop("_meta", {})
    if meta.get("profile") != "inventory_legacy":
        raise SourceError("unexpected output format from ansible-inventory")
    warnings: list[str] = []
    hostvars = meta.get("hostvars") or {}
    if not isinstance(hostvars, dict):
        raise SourceError("unexpected output from ansible-inventory")

    hosts: dict[str, dict] = {}
    skipped: set[str] = set()

    def add_host(name: Any) -> bool:
        if name in hosts:
            return True
        if name in skipped:
            return False
        if problem := hostname_problem(name):
            skipped.add(name)
            _warn(warnings, f"skipped host {str(name)[:100]!r}: its name {problem}")
            return False
        if len(hosts) >= settings.inventory_max_hosts:
            raise SourceError(f"more than {settings.inventory_max_hosts} hosts")
        hosts[name] = {}
        return True

    for name, host_vars in hostvars.items():
        if add_host(name):
            hosts[name] = _parse_vars(host_vars, f"host {name}", warnings)

    all_vars: dict = {}
    raw_groups: dict[str, dict] = {}
    for name, group in data.items():
        if not isinstance(group, dict):
            raise SourceError("unexpected output from ansible-inventory")
        if name == "all":
            all_vars = _parse_vars(group.get("vars") or {}, "group all", warnings)
            continue
        if name == "ungrouped":
            for host in _names(group.get("hosts")):
                add_host(host)
            continue
        if problem := group_problem(name):
            _warn(warnings, f"skipped group {str(name)[:100]!r}: its name {problem}")
            continue
        raw_groups[name] = group
    if len(raw_groups) > settings.inventory_max_groups:
        raise SourceError(f"more than {settings.inventory_max_groups} groups")

    groups: dict[str, dict] = {}
    edges = 0
    for name, group in raw_groups.items():
        members = [h for h in _names(group.get("hosts")) if add_host(h)]
        children = [c for c in _names(group.get("children")) if c in raw_groups]
        edges += len(members) + len(children)
        if edges > MAX_EDGES:
            raise SourceError(f"more than {MAX_EDGES} group memberships")
        groups[name] = {
            "hosts": list(dict.fromkeys(members)),
            "children": list(dict.fromkeys(children)),
            "vars": _parse_vars(group.get("vars") or {}, f"group {name}", warnings),
        }
    _refuse_cycles(groups)
    return {"vars": all_vars, "hosts": hosts, "groups": groups}, warnings


def filter_graph(graph: dict, static_hosts: list[str], warnings: list[str]) -> dict:
    """The snapshot: the graph without the Ansible settings sources may not set, and the
    inventory's own hosts it was made with."""
    static = set(static_hosts)
    return {
        "vars": _filter_vars(graph["vars"], "group all", warnings),
        "hosts": {
            name: _filter_vars(host_vars, f"host {name}", warnings, quiet=name in static)
            for name, host_vars in graph["hosts"].items()
        },
        "groups": {
            name: {
                "hosts": group["hosts"],
                "children": group["children"],
                "vars": _filter_vars(group["vars"], f"group {name}", warnings),
            }
            for name, group in graph["groups"].items()
        },
        "static_hosts": list(static_hosts),
    }


def normalise(raw: bytes, static_hosts: list[str]) -> tuple[dict, list[str]]:
    """ansible-inventory output as a snapshot ({"vars", "hosts", "groups", "static_hosts"})
    plus warnings, or SourceError (parse_output, then filter_graph)."""
    graph, warnings = parse_output(raw)
    return filter_graph(graph, static_hosts, warnings), warnings


def _names(value: Any) -> list[str]:
    """A group's host or child names: ansible-inventory only ever writes lists of strings."""
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(name, str) for name in value):
        raise SourceError("unexpected output from ansible-inventory")
    return value


def _refuse_cycles(groups: dict[str, dict]) -> None:
    state: dict[str, int] = {}  # 1: on the current path, 2: done
    for root in groups:
        if root in state:
            continue
        stack = [(root, iter(groups[root]["children"]))]
        state[root] = 1
        while stack:
            name, children = stack[-1]
            child = next(children, None)
            if child is None:
                state[name] = 2
                stack.pop()
            elif state.get(child) == 1:
                raise SourceError(f"group {child!r} contains itself")
            elif child not in state:
                state[child] = 1
                stack.append((child, iter(groups[child]["children"])))


# --- per-source outputs and the combine ------------------------------------------------------
#
# Each source's output is kept on its own (parsed, Ansible settings still in), so a refresh
# can combine what every source found last with the inventory's own hosts: the sources that
# didn't run or failed keep contributing their last good output. Without constructed sources
# the API layers them itself, as ansible-inventory does when it loads several inventories in
# order (later wins per variable, group members and children are unions in first-seen order);
# with them, a worker runs ansible-inventory once more over the outputs (every string
# `!unsafe`: never a template), the inventory's own hosts and the constructed configs.


def store_source_output(
    db: Session, refresh: InventoryRefresh, row: InventoryRefreshSource, raw: bytes
) -> None:
    """A source's output from this refresh becomes its last good output, unless it can't be
    used (the source failed) or the source changed since the job was built (stale). The caller
    holds the refresh's lock and commits."""
    try:
        graph, warnings = parse_output(raw)
    except SourceError as exc:
        record_source_failure(db, row, str(exc))
        return
    source = db.get(InventorySource, row.source_id) if row.source_id is not None else None
    if source is None or input_sha256(source) != row.input_sha256:
        row.status = "stale"  # deleted or edited meanwhile: the next refresh runs it again
        return
    previous = db.get(InventorySourceOutput, source.id)
    if (
        previous is not None
        and previous.host_count
        and len(graph["hosts"]) < previous.host_count / 2
    ):
        _warn(
            warnings,
            f"{len(graph['hosts'])} hosts, down from {previous.host_count} last time: "
            "check its filters and credential",
        )
    values = {
        "inventory_id": source.inventory_id,
        "refresh_id": refresh.id,
        "data": graph,
        "sha256": hashlib.sha256(json.dumps(graph, sort_keys=True).encode()).hexdigest(),
        "host_count": len(graph["hosts"]),
        "group_count": len(graph["groups"]),
        "output_bytes": len(raw),
        "warnings": warnings,
        "input_sha256": row.input_sha256,
        "refreshed_at": func.now(),
    }
    if previous is None:
        db.add(InventorySourceOutput(source_id=source.id, **values))
    else:
        for key, value in values.items():
            setattr(previous, key, value)
    row.status, row.error, row.host_count = "success", None, len(graph["hosts"])
    source.last_error, source.last_finished_at = None, func.now()


def record_source_failure(db: Session, row: InventoryRefreshSource, error: str) -> None:
    """The source keeps its last good output; its error shows until it works again."""
    row.status, row.error = "failed", error[:1000]
    source = db.get(InventorySource, row.source_id) if row.source_id is not None else None
    if source is not None and input_sha256(source) == row.input_sha256:
        source.last_error, source.last_finished_at = row.error, func.now()


def refresh_rows(db: Session, refresh: InventoryRefresh) -> list[InventoryRefreshSource]:
    return list(
        db.scalars(
            select(InventoryRefreshSource)
            .where(InventoryRefreshSource.refresh_id == refresh.id)
            .order_by(InventoryRefreshSource.id)
        )
    )


def _contributing(
    db: Session, inventory: Inventory
) -> list[tuple[InventorySource, InventorySourceOutput]]:
    """The enabled sources' last good outputs, in the order ansible-inventory reads them."""
    plain = [s for s in ordered_sources(inventory) if not is_constructed(s)]
    outputs = {
        output.source_id: output
        for output in db.scalars(
            select(InventorySourceOutput).where(
                InventorySourceOutput.source_id.in_([s.id for s in plain])
            )
        )
    }
    return [(source, outputs[source.id]) for source in plain if source.id in outputs]


def _source_warnings(pairs: list[tuple[InventorySource, InventorySourceOutput]]) -> list[str]:
    warnings: list[str] = []
    for source, output in pairs:
        for warning in output.warnings or []:
            _warn(warnings, f"source '{source.name}': {warning}")
    return warnings


def _layer(graphs: list[dict]) -> dict:
    """Graphs loaded in order, as ansible-inventory combines inventories."""
    all_vars: dict = {}
    hosts: dict[str, dict] = {}
    groups: dict[str, dict] = {}
    for graph in graphs:
        all_vars.update(graph.get("vars") or {})
        for name, host_vars in graph["hosts"].items():
            hosts.setdefault(name, {}).update(host_vars or {})
        for name, group in graph["groups"].items():
            into = groups.setdefault(name, {"hosts": {}, "children": {}, "vars": {}})
            into["hosts"].update(dict.fromkeys(group["hosts"]))
            into["children"].update(dict.fromkeys(group["children"]))
            into["vars"].update(group.get("vars") or {})
    return {
        "vars": all_vars,
        "hosts": hosts,
        "groups": {
            name: {"hosts": list(g["hosts"]), "children": list(g["children"]), "vars": g["vars"]}
            for name, g in groups.items()
        },
    }


def _legacy_json(graph: dict) -> bytes:
    """A graph as ansible-inventory --list --export writes it: names sorted (it sorts keys),
    hosts without vars only in their groups (or "ungrouped": those in no group, in the order
    they were added). parse_output then reads the hosts in ansible's order too."""
    grouped = {host for group in graph["groups"].values() for host in group["hosts"]}
    out: dict = {
        "_meta": {
            "profile": "inventory_legacy",
            "hostvars": {
                name: graph["hosts"][name]
                for name in sorted(graph["hosts"])
                if graph["hosts"][name]
            },
        },
        "all": {"vars": graph["vars"]} if graph["vars"] else {},
        "ungrouped": {"hosts": [name for name in graph["hosts"] if name not in grouped]},
    }
    for name in sorted(graph["groups"]):
        group = graph["groups"][name]
        out[name] = {key: group[key] for key in ("hosts", "children", "vars") if group[key]}
    return json.dumps(out).encode()


def needs_combine_job(inventory: Inventory) -> bool:
    """Whether the combine runs in a worker (constructed sources are Jinja over the data)."""
    return any(is_constructed(s) for s in ordered_sources(inventory))


def combine_here(
    db: Session, refresh: InventoryRefresh, inventory: Inventory
) -> tuple[dict, list[str]]:
    """The snapshot of an inventory without constructed sources: its sources' last good
    outputs and its own hosts, layered here (SourceError when over the limits)."""
    static = static_data(inventory)
    pairs = _contributing(db, inventory)
    warnings = _source_warnings(pairs)
    graph = _layer([output.data for _, output in pairs] + [merge(static)])
    snapshot, more = normalise(_legacy_json(graph), list(static["hosts"]))
    refresh.sources = {**(refresh.sources or {}), "static_hosts": list(static["hosts"])}
    return snapshot, warnings + more


def build_combine_job(db: Session, refresh: InventoryRefresh, inventory: Inventory) -> dict:
    """Stage two, for an inventory with constructed sources: the sources' last good outputs
    (strings `!unsafe`), the inventory's own hosts (likewise: operators write them, but the
    refresh holds the constructed sources' credentials), then the constructed configs."""
    static = static_data(inventory)
    files = []
    for order, (source, output) in enumerate(_contributing(db, inventory), start=100):
        data = output.data
        graph = {
            "vars": mark_unsafe(data["vars"]),
            "hosts": {name: mark_unsafe(host_vars) for name, host_vars in data["hosts"].items()},
            "groups": {
                name: {**group, "vars": mark_unsafe(group["vars"])}
                for name, group in data["groups"].items()
            },
        }
        files.append({"name": f"{order:03d}-src{source.id}.out.yml", "text": render(graph)})
    graph = merge(static)
    graph["hosts"] = {name: mark_unsafe(host_vars) for name, host_vars in graph["hosts"].items()}
    files.append({"name": "500-static.yml", "text": render(graph)})
    deadline = new_deadline()
    env: dict[str, str] = {}
    secrets: set[str] = set()
    constructed = [s for s in ordered_sources(inventory) if is_constructed(s)]
    for order, source in enumerate(constructed, start=600):
        values = _source_env(db, inventory, source, deadline)
        for name, value in values.items():
            if env.get(name, value) != value:
                raise SourceError(f"two credentials set {name} to different values")
        env.update(values)
        secrets.update(values.values())
        files.append({"name": config_file_name(source, order), "text": source.config})
    refresh.stage = "combine"
    refresh.sources = {**(refresh.sources or {}), "static_hosts": list(static["hosts"])}
    return {
        "calls": [{"key": "combined", "kind": "combine", "files": files, "env": env}],
        "secrets": sorted(secrets),
        "max_output_bytes": get_settings().inventory_max_output_mb * 1024 * 1024,
    }


def combine_warnings(db: Session, inventory: Inventory) -> list[str]:
    """The sources' own warnings, for a snapshot made by a combine job."""
    return _source_warnings(_contributing(db, inventory))


def sources_outcome(rows: list[InventoryRefreshSource]) -> tuple[str, str | None]:
    """The refresh's status from what its sources did: failed if any of them failed."""
    errors = [f"source '{r.name}': {r.error or 'failed'}" for r in rows if r.status == "failed"]
    if errors:
        return RunStatus.FAILED.value, "\n".join(errors)[:1000]
    return RunStatus.SUCCESS.value, None


def keep_current_snapshot(
    db: Session, inventory: Inventory, rows: list[InventoryRefreshSource]
) -> bool:
    """Whether to keep the inventory's current snapshot rather than store a combined one: when
    no source worked this time (nothing new), or when a failed source has no output of its own
    yet but contributed to the current snapshot (one from before sources ran on their own),
    whose hosts the combination would lose."""
    ran = [r for r in rows if r.ran]
    if ran and not any(r.status in ("success", "stale") for r in ran):
        return True
    current = (
        db.get(InventorySnapshot, inventory.current_snapshot_id)
        if inventory.current_snapshot_id
        else None
    )
    if current is None:
        return False
    in_current = {entry.get("id") for entry in current.sources or []}
    with_output = set(
        db.scalars(
            select(InventorySourceOutput.source_id).where(
                InventorySourceOutput.inventory_id == inventory.id
            )
        )
    )
    return any(
        r.status == "failed" and r.source_id in in_current and r.source_id not in with_output
        for r in rows
    )


def store_snapshot(
    db: Session, refresh: InventoryRefresh, snapshot: dict, warnings: list[str]
) -> InventorySnapshot:
    """Makes it the inventory's current snapshot (the caller commits)."""
    inventory = db.scalars(
        select(Inventory).where(Inventory.id == refresh.inventory_id).with_for_update()
    ).one()
    previous = (
        db.get(InventorySnapshot, inventory.current_snapshot_id)
        if (inventory.current_snapshot_id)
        else None
    )
    if (
        previous is not None
        and previous.host_count
        and len(snapshot["hosts"]) < (previous.host_count / 2)
    ):
        warnings.append(
            f"{len(snapshot['hosts'])} hosts, down from {previous.host_count} last time: "
            "check the sources' filters and credentials"
        )
    encoded = json.dumps(snapshot, sort_keys=True).encode()
    row = InventorySnapshot(
        inventory_id=inventory.id,
        refresh_id=refresh.id,
        data=snapshot,
        sha256=hashlib.sha256(encoded).hexdigest(),
        host_count=len(snapshot["hosts"]),
        group_count=len(snapshot["groups"]),
        warnings=warnings,
        sources=(refresh.sources or {}).get("sources", []),
    )
    db.add(row)
    db.flush()
    if previous is not None:
        previous.superseded_at = func.now()
    inventory.current_snapshot_id = row.id
    refresh.snapshot_id = row.id
    return row


def prune_snapshots(db: Session) -> int:
    """Deletes superseded snapshots beyond the last few of each inventory, unless a queued or
    running run has pinned them (the caller commits)."""
    ranked = (
        select(
            InventorySnapshot.id,
            func.row_number()
            .over(
                partition_by=InventorySnapshot.inventory_id,
                order_by=InventorySnapshot.id.desc(),
            )
            .label("n"),
        )
        .where(InventorySnapshot.superseded_at.is_not(None))
        .subquery()
    )
    pinned = select(Run.inventory_snapshot_id).where(
        Run.status.in_((RunStatus.QUEUED.value, RunStatus.RUNNING.value)),
        Run.inventory_snapshot_id.is_not(None),
    )
    doomed = list(
        db.scalars(
            select(ranked.c.id).where(ranked.c.n >= KEEP_SNAPSHOTS, ranked.c.id.not_in(pinned))
        )
    )
    if doomed:
        db.execute(
            update(InventoryRefresh)
            .where(InventoryRefresh.snapshot_id.in_(doomed))
            .values(snapshot_id=None)
        )
        db.query(InventorySnapshot).filter(InventorySnapshot.id.in_(doomed)).delete(
            synchronize_session=False
        )
    return len(doomed)


def _release_waiting_runs(
    db: Session, refresh: InventoryRefresh, status: str, error: str | None
) -> None:
    """The runs that asked for this refresh: they get the snapshot it made (their target group
    checked again), or fail with it. The caller commits; the queue is woken after."""
    from app.inventory_render import merge
    from app.queue import fail_run

    waiting = db.scalars(
        select(Run)
        .where(Run.waiting_refresh_id == refresh.id, Run.status == RunStatus.QUEUED.value)
        .order_by(Run.id)
        .with_for_update()
    ).all()
    snapshot = (
        db.get(InventorySnapshot, refresh.snapshot_id)
        if status == RunStatus.SUCCESS.value and refresh.snapshot_id is not None
        else None
    )
    for run in waiting:
        if snapshot is None:
            why = (error or status.replace("_", " ")).splitlines()[0][:300]
            fail_run(run, RunStatus.FAILED, f"not run: the inventory refresh failed: {why}")
            continue
        graph = merge(run.inventory_static or {"hosts": {}, "groups": {}}, snapshot.data)
        if run.group_name is not None and run.group_name not in graph["groups"]:
            fail_run(
                run,
                RunStatus.FAILED,
                f"not run: its target group {run.group_name!r} is not in the refreshed inventory",
            )
            continue
        run.inventory_snapshot_id = snapshot.id
        run.inventory_snapshot_at = snapshot.created_at
        run.inventory_snapshot_hosts = snapshot.host_count


def end_refresh(
    db: Session, refresh: InventoryRefresh, status: str, error: str | None = None
) -> dict | None:
    """Ends a refresh (the caller holds its row lock and commits): its status, the metrics and
    the inventory's refresh alert (raised once per failure streak, cleared by the next
    success). Returns the audit event to record after the commit when a failure streak
    starts (app.audit.record commits by itself)."""
    from app import metrics
    from app.notifications.ops import inventory_refresh_failed, inventory_refresh_ok

    refresh.status = status
    refresh.error = error[:1000] if error else None
    refresh.finished_at = func.now()
    refresh.lease_expires_at = None
    refresh.claim_token_hash = None
    refresh.job_token_hash = None
    seconds = None
    if refresh.started_at is not None:
        seconds = (db.scalar(select(func.now())) - refresh.started_at).total_seconds()
    metrics.inventory_refresh_finished(status, seconds)
    _release_waiting_runs(db, refresh, status, error)
    inventory = db.get(Inventory, refresh.inventory_id)
    if inventory is None:
        return None
    try:
        with db.begin_nested():  # a notification must never fail the refresh's own commit
            if status == RunStatus.SUCCESS.value:
                # Not while another source is still failing: its last refresh raised it.
                if not any(source.enabled and source.last_error for source in inventory.sources):
                    inventory_refresh_ok(db, inventory)
            elif inventory_refresh_failed(db, inventory, error or status):
                return {
                    "action": "inventory.refresh",
                    "outcome": "failure",
                    "actor_username": refresh.worker_id,
                    "target_type": "inventory",
                    "target_id": inventory.id,
                    "target_name": inventory.name,
                    "project_id": inventory.project_id,
                    "detail": {"refresh_id": refresh.id, "error": (error or status)[:300]},
                }
    except Exception:
        logger.exception("could not notify about refresh %s", refresh.id)
    return None
