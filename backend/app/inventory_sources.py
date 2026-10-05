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
from app.env_credentials import resolve_env
from app.inventory_render import group_problem, hostname_problem, merge, render, static_data
from app.models import (
    Credential,
    Inventory,
    InventoryRefresh,
    InventorySnapshot,
    InventorySource,
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
TRIGGERS = ("manual", "schedule", "sources_changed", "static_changed")
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
    if plugin in _DENIED or plugin.removeprefix("ansible.builtin.") in _DENIED:
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
    db: Session, inventory: Inventory, trigger: str, requested_by: str | None = None
) -> int | None:
    """Queues a refresh (the caller commits and wakes the workers). A request while one is
    already queued merges into it: returns None then, or when there is nothing to refresh."""
    if not has_sources(db, inventory.id):
        return None
    stmt = (
        insert(InventoryRefresh)
        .values(
            inventory_id=inventory.id,
            project_id=inventory.project_id,
            status=RunStatus.QUEUED.value,
            trigger=trigger,
            requested_by=requested_by,
            timeout_seconds=get_settings().inventory_refresh_timeout_seconds,
        )
        .on_conflict_do_nothing(
            index_elements=[InventoryRefresh.inventory_id],
            index_where=text("status = 'queued'"),
        )
        .returning(InventoryRefresh.id)
    )
    return db.scalar(stmt)


def due_inventories(db: Session) -> list[Inventory]:
    """Inventories whose refresh interval has passed since their last refresh was queued."""
    last = (
        select(func.max(InventoryRefresh.queued_at))
        .where(InventoryRefresh.inventory_id == Inventory.id)
        .scalar_subquery()
    )
    interval = func.make_interval(0, 0, 0, 0, 0, 0, Inventory.refresh_interval_seconds)
    return list(
        db.scalars(
            select(Inventory).where(
                Inventory.refresh_interval_seconds > 0,
                exists().where(
                    InventorySource.inventory_id == Inventory.id, InventorySource.enabled
                ),
                (last.is_(None)) | (last + interval <= func.now()),
            )
        )
    )


# --- the job ------------------------------------------------------------------------------


def build_refresh_job(db: Session, refresh: InventoryRefresh) -> dict:
    """What the worker runs: the config files in order, the credentials' variables, and the
    values to scrub from the output. SecretStoreError (with `.subject`) when a credential in
    the secret store can't be read."""
    inventory = db.get(Inventory, refresh.inventory_id)
    if inventory is None or inventory.project_id != refresh.project_id:
        raise RuntimeError(f"refresh {refresh.id}: its inventory is gone or moved")
    sources = ordered_sources(inventory)
    if not sources:
        raise SourceError("the inventory has no enabled sources")
    deadline = new_deadline()
    env: dict[str, str] = {}
    secrets: set[str] = set()
    for source in sources:
        if source.credential_id is None:
            continue
        credential = db.get(Credential, source.credential_id)
        if credential is None or credential.project_id != inventory.project_id:
            raise RuntimeError(f"refresh {refresh.id}: a credential is not in its project")
        if credential.kind != "env":
            raise SourceError(f"source '{source.name}': its credential is not env variables")
        try:
            values = resolve_env(credential, deadline)
        except SecretStoreError as exc:
            exc.subject = f"credential '{credential.name}'"
            raise
        for name, value in values.items():
            if env.get(name, value) != value:
                raise SourceError(f"two credentials set {name} to different values")
        env.update(values)
        secrets.update(values.values())

    static = static_data(inventory)
    files = []
    plain = [s for s in sources if not is_constructed(s)]
    for order, source in enumerate(plain, start=10):
        files.append({"name": config_file_name(source, order), "text": source.config})
    files.append({"name": "50-static.yml", "text": render(merge(static))})
    for order, source in enumerate((s for s in sources if is_constructed(s)), start=60):
        files.append({"name": config_file_name(source, order), "text": source.config})
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
        "files": files,
        "env": env,
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


def _vars(value: Any, where: str, warnings: list[str]) -> dict:
    if not isinstance(value, dict):
        raise SourceError(f"{where}: vars must be a mapping")
    out = {}
    for key, item in value.items():
        try:
            out[str(key)] = _unwrap(item, 1)
        except _Vaulted:
            _warn(warnings, f"{where}: dropped {key}, a vault-encrypted value")
    return out


def _warn(warnings: list[str], message: str) -> None:
    if len(warnings) < _MAX_WARNINGS:
        warnings.append(message[:300])
    elif len(warnings) == _MAX_WARNINGS:
        warnings.append("… more warnings not shown")


def normalise(raw: bytes, static_hosts: list[str]) -> tuple[dict, list[str]]:
    """ansible-inventory --list --export output as a snapshot ({"vars", "hosts", "groups",
    "static_hosts"}) plus warnings, or SourceError. Names ansible would read differently are
    skipped with a warning; anything over the limits fails the refresh."""
    settings = get_settings()
    if len(raw) > settings.inventory_max_output_mb * 1024 * 1024:
        raise SourceError(f"the output is larger than {settings.inventory_max_output_mb} MiB")
    try:
        data = json.loads(raw)
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
            hosts[name] = _vars(host_vars, f"host {name}", warnings)

    all_vars: dict = {}
    raw_groups: dict[str, dict] = {}
    for name, group in data.items():
        if not isinstance(group, dict):
            raise SourceError("unexpected output from ansible-inventory")
        if name == "all":
            all_vars = _vars(group.get("vars") or {}, "group all", warnings)
            continue
        if name == "ungrouped":
            for host in group.get("hosts") or ():
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
            "vars": _vars(group.get("vars") or {}, f"group {name}", warnings),
        }
    _refuse_cycles(groups)
    return {
        "vars": all_vars,
        "hosts": hosts,
        "groups": groups,
        "static_hosts": list(static_hosts),
    }, warnings


def _names(value: Any) -> list:
    if value is None:
        return []
    if not isinstance(value, list):
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
    inventory = db.get(Inventory, refresh.inventory_id)
    if inventory is None:
        return None
    try:
        with db.begin_nested():  # a notification must never fail the refresh's own commit
            if status == RunStatus.SUCCESS.value:
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
    except Exception:  # noqa: BLE001
        logger.exception("could not notify about refresh %s", refresh.id)
    return None
