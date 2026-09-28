"""ansible-galaxy role/collection installs.

ansible-galaxy runs as a subprocess — never import ansible.cli here (it crashes
with a blocking-IO error outside a real terminal). Installed content lives in a
persistent shared dir, which workers mount read-only; the API process is its only writer.

Installs wait their turn like runs do: a new install is queued, no new run is claimed from then
on, and the install starts once the running runs have finished (try_start_install()).
"""

import json
import os
import re
import signal
import subprocess
import sys
import threading
from pathlib import Path
from urllib.parse import urlsplit

import yaml
from sqlalchemy import func, select, text, update

from app.config import get_settings
from app.db import GALAXY_GATE_KEY, get_sessionmaker
from app.models import GalaxyInstall, Run, RunStatus
from app.notify import notifier
from app.storage import (
    galaxy_collections_dir,
    galaxy_install_log_path,
    galaxy_roles_dir,
)
from app.subprocess_env import clean_env

MAX_REQUIREMENTS_BYTES = 64 * 1024
MAX_ENTRIES = 100
INSTALL_TIMEOUT_SECONDS = 600

_FQCN = re.compile(r"^[a-z0-9_]+\.[a-z0-9_]+$")
_GALAXY_ROLE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_-]*\.[A-Za-z0-9_][A-Za-z0-9_.-]*$")
_LOCAL_ROLE_DIRNAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$")
_VERSION = re.compile(r"^[A-Za-z0-9._+~<>=!*][A-Za-z0-9._+~<>=!,*/ -]{0,199}$")


class RequirementsError(ValueError):
    pass


def _check_https_url(value: str, what: str, allow_git_prefix: bool = False) -> None:
    candidate = value
    if allow_git_prefix and candidate.startswith("git+"):
        candidate = candidate[len("git+") :]
    parts = urlsplit(candidate)
    if parts.scheme != "https" or not parts.hostname or any(c.isspace() or c == "," for c in value):
        raise RequirementsError(f"{what} must be an https:// URL (got {value!r})")
    if parts.username or parts.password:
        raise RequirementsError(f"{what} must not embed credentials")


def _check_version(entry: dict, what: str) -> None:
    if "version" not in entry:
        return
    version = entry["version"]
    if not isinstance(version, str):
        raise RequirementsError(f'{what}: version must be a quoted string (e.g. version: "1.10.0")')
    if not _VERSION.match(version):
        raise RequirementsError(f"{what}: invalid version {version!r}")


def _check_keys(entry: dict, allowed: set[str], what: str) -> None:
    unknown = set(entry) - allowed
    if unknown:
        raise RequirementsError(
            f"{what}: unsupported key(s): {', '.join(sorted(map(str, unknown)))}"
        )


def _validate_collection(entry: object, allow_local: bool) -> None:
    if isinstance(entry, str):
        if not allow_local and not _FQCN.match(entry):
            raise RequirementsError(
                f"collection {entry!r} must be a Galaxy name like namespace.name "
                "(use a mapping with type: url or git for URLs)"
            )
        return
    if not isinstance(entry, dict):
        raise RequirementsError("each collection must be a name string or a mapping")

    what = f"collection {entry.get('name')!r}"
    _check_keys(entry, {"name", "version", "type", "source"}, what)
    name = entry.get("name")
    if not isinstance(name, str) or not name:
        raise RequirementsError("each collection mapping needs a string 'name'")
    _check_version(entry, what)
    if allow_local:
        return

    ctype = entry.get("type", "galaxy")
    if ctype == "galaxy":
        if not _FQCN.match(name):
            raise RequirementsError(f"{what}: must be a Galaxy name like namespace.name")
    elif ctype in ("url", "git"):
        _check_https_url(name, f"{what} name", allow_git_prefix=ctype == "git")
    else:
        raise RequirementsError(
            f"{what}: type {ctype!r} is not allowed (only galaxy, url, git — "
            "local file/dir sources are rejected)"
        )
    if "source" in entry:
        source = entry["source"]
        if not isinstance(source, str):
            raise RequirementsError(f"{what}: source must be a string")
        _check_https_url(source, f"{what} source")


def _check_role_src(src: str, what: str) -> None:
    if _GALAXY_ROLE.match(src):
        return
    if src.startswith(("https://", "git+https://")):
        _check_https_url(src, f"{what} src", allow_git_prefix=True)
        return
    raise RequirementsError(
        f"{what}: src must be a Galaxy name like namespace.role or an https:// / git+https:// URL"
    )


def _validate_role(entry: object, allow_local: bool) -> None:
    if isinstance(entry, str):
        if not allow_local:
            _check_role_src(entry, f"role {entry!r}")
        return
    if not isinstance(entry, dict):
        raise RequirementsError("each role must be a name string or a mapping")

    what = f"role {entry.get('name') or entry.get('src')!r}"
    _check_keys(entry, {"name", "src", "version", "scm"}, what)
    _check_version(entry, what)
    name, src = entry.get("name"), entry.get("src")
    if not isinstance(name or src, str) or not (name or src):
        raise RequirementsError("each role mapping needs a string 'name' or 'src'")
    if allow_local:
        return

    if src is not None:
        if not isinstance(src, str):
            raise RequirementsError(f"{what}: src must be a string")
        _check_role_src(src, what)
        if name is not None and (not isinstance(name, str) or not _LOCAL_ROLE_DIRNAME.match(name)):
            raise RequirementsError(f"{what}: name may only contain letters, digits, _ . -")
    else:
        _check_role_src(name, what)
    if entry.get("scm", "git") != "git":
        raise RequirementsError(f"{what}: only scm: git is supported")


def validate_requirements(text: str) -> dict[str, list]:
    if len(text.encode()) > MAX_REQUIREMENTS_BYTES:
        raise RequirementsError(f"requirements exceed {MAX_REQUIREMENTS_BYTES // 1024}KB")
    try:
        parsed = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise RequirementsError(f"Invalid YAML: {exc}") from exc

    if parsed is None:
        return {"collections": [], "roles": []}
    if not isinstance(parsed, dict):
        raise RequirementsError(
            "requirements must be a mapping with 'collections:' and/or 'roles:'"
        )
    unknown = set(parsed) - {"collections", "roles"}
    if unknown:
        raise RequirementsError(
            f"unsupported top-level key(s): {', '.join(sorted(map(str, unknown)))} "
            "(only 'collections' and 'roles' are allowed)"
        )

    collections = parsed.get("collections") or []
    roles = parsed.get("roles") or []
    if not isinstance(collections, list) or not isinstance(roles, list):
        raise RequirementsError("'collections' and 'roles' must each be a list")
    if len(collections) + len(roles) > MAX_ENTRIES:
        raise RequirementsError(f"too many entries (max {MAX_ENTRIES})")

    allow_local = get_settings().galaxy_allow_local_sources
    for entry in collections:
        _validate_collection(entry, allow_local)
    for entry in roles:
        _validate_role(entry, allow_local)
    return {"collections": collections, "roles": roles}


def galaxy_env() -> dict[str, str]:
    return {
        "ANSIBLE_COLLECTIONS_PATH": str(galaxy_collections_dir()),
        "ANSIBLE_ROLES_PATH": str(galaxy_roles_dir()),
    }


def _install_env() -> dict[str, str]:
    return clean_env(
        {
            **galaxy_env(),
            "ANSIBLE_NOCOLOR": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ALLOW_PROTOCOL": "https",
        }
    )


def _galaxy_binary() -> str:
    candidate = Path(sys.executable).parent / "ansible-galaxy"
    return str(candidate) if candidate.exists() else "ansible-galaxy"


def _install_commands(requirements: dict[str, list], requirements_file: Path, upgrade: bool):
    binary = _galaxy_binary()
    commands = []
    if requirements["collections"]:
        cmd = [binary, "collection", "install", "-r", str(requirements_file)]
        cmd += ["-p", str(galaxy_collections_dir()), "--timeout", "60"]
        if upgrade:
            cmd.append("--upgrade")
        commands.append(cmd)
    if requirements["roles"]:
        cmd = [binary, "role", "install", "-r", str(requirements_file)]
        cmd += ["-p", str(galaxy_roles_dir()), "--timeout", "60"]
        if upgrade:
            cmd.append("--force")
        commands.append(cmd)
    return commands


def _run_command(cmd: list[str], env: dict[str, str], log) -> int:
    log.write(f"$ {' '.join(cmd)}\n")
    log.flush()
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        env=env,
        text=True,
    )

    def _kill() -> None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        log.write(f"\n[killed: exceeded {INSTALL_TIMEOUT_SECONDS}s]\n")

    timer = threading.Timer(INSTALL_TIMEOUT_SECONDS, _kill)
    timer.start()
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            log.write(line)
            log.flush()
        return proc.wait()
    finally:
        timer.cancel()


def _renew_install_lease(install_id: int, stop: threading.Event) -> None:
    lease = get_settings().run_lease_seconds
    while not stop.wait(lease / 4):
        db = get_sessionmaker()()
        try:
            db.execute(
                update(GalaxyInstall)
                .where(
                    GalaxyInstall.id == install_id,
                    GalaxyInstall.status == RunStatus.RUNNING.value,
                )
                .values(lease_expires_at=func.now() + func.make_interval(0, 0, 0, 0, 0, 0, lease))
            )
            db.commit()
        except Exception:  # noqa: BLE001 - a missed renewal only shortens the lease
            db.rollback()
        finally:
            db.close()


def run_install(install_id: int) -> None:
    """Runs an install that try_start_install() has already marked running."""
    db = get_sessionmaker()()
    install = db.get(GalaxyInstall, install_id)
    if install is None:
        db.close()
        return

    stop_renewing = threading.Event()
    threading.Thread(
        target=_renew_install_lease, args=(install_id, stop_renewing), daemon=True
    ).start()
    try:
        return_code = 0
        with galaxy_install_log_path(install_id).open("w", encoding="utf-8") as log:
            try:
                requirements = validate_requirements(install.requirements_snapshot)
                scratch = galaxy_install_log_path(install_id).with_suffix(".requirements.yml")
                scratch.write_text(install.requirements_snapshot)
                try:
                    env = _install_env()
                    for cmd in _install_commands(requirements, scratch, install.upgrade):
                        rc = _run_command(cmd, env, log)
                        if rc != 0 and return_code == 0:
                            return_code = rc
                finally:
                    scratch.unlink(missing_ok=True)
            except Exception as exc:  # noqa: BLE001 - surface any failure in the log
                log.write(f"\n[install error: {exc}]\n")
                return_code = return_code or 1

        install.return_code = return_code
        install.status = RunStatus.SUCCESS.value if return_code == 0 else RunStatus.FAILED.value
    except Exception:
        install.status = RunStatus.FAILED.value
        raise
    finally:
        stop_renewing.set()
        install.finished_at = func.now()
        install.lease_expires_at = None
        db.commit()
        db.close()
        notifier.notify("queue")  # runs may be claimed again
        try_start_install()  # the next queued install, if any


def try_start_install() -> int | None:
    """Starts the oldest queued install if none is running and no run is running; returns its
    id. Called when an install is queued, after each run ends, and by the reaper."""
    db = get_sessionmaker()()
    try:
        db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": GALAXY_GATE_KEY})
        running = GalaxyInstall.status == RunStatus.RUNNING.value
        if db.scalar(select(GalaxyInstall.id).where(running).limit(1)) is not None:
            return None
        install = db.scalars(
            select(GalaxyInstall)
            .where(GalaxyInstall.status == RunStatus.QUEUED.value)
            .order_by(GalaxyInstall.id)
            .limit(1)
        ).first()
        if install is None:
            return None
        if db.scalar(select(Run.id).where(Run.status == RunStatus.RUNNING.value).limit(1)):
            return None  # waits for the running runs; no new ones are claimed meanwhile
        lease = get_settings().run_lease_seconds
        install.status = RunStatus.RUNNING.value
        install.started_at = func.now()
        install.lease_expires_at = func.now() + func.make_interval(0, 0, 0, 0, 0, 0, lease)
        db.commit()
        install_id = install.id
    finally:
        db.rollback()
        db.close()
    threading.Thread(target=run_install, args=(install_id,), daemon=True).start()
    return install_id


def list_installed_collections() -> list[dict[str, str | None]]:
    root = galaxy_collections_dir() / "ansible_collections"
    found = []
    if root.is_dir():
        for manifest in sorted(root.glob("*/*/MANIFEST.json")):
            version = None
            try:
                version = json.loads(manifest.read_text())["collection_info"]["version"]
            except (OSError, ValueError, KeyError, TypeError):
                pass
            found.append(
                {
                    "name": f"{manifest.parent.parent.name}.{manifest.parent.name}",
                    "version": version,
                }
            )
    return found


def list_installed_roles() -> list[dict[str, str | None]]:
    root = galaxy_roles_dir()
    found = []
    for role_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        version = None
        info = role_dir / "meta" / ".galaxy_install_info"
        try:
            data = yaml.safe_load(info.read_text())
            if isinstance(data, dict) and data.get("version"):
                version = str(data["version"])
        except (OSError, yaml.YAMLError):
            pass
        found.append({"name": role_dir.name, "version": version})
    return found
