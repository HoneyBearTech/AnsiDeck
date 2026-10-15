"""Inventory files and scripts from a git source (dynamic inventory sources of kind "git_file"
and "git_script").

A file source: an INI or
YAML inventory file, or a directory of them, in a synced repository, read from the git source's
current commit when a refresh's job is built. The API sends the file (or the directory's files)
and the group_vars/ and host_vars/ beside it in the job, as text; the worker runs
ansible-inventory with only the yaml and ini plugins over them. Nothing else of the repository
reaches the refresh: not its ansible.cfg, plugins or scripts.

A script source: an inventory script (a "#!" line naming its interpreter) and everything in its
directory and below, bounded the same way, run through that interpreter as the worker slot's
user with only its own source's credential (app.run_worker._script_inventory). Whoever can
commit to the repository can make it do anything a playbook in that slot could.

What comes out is a source's output like any other: untrusted, its Ansible settings dropped,
its strings never templated.
"""

import hashlib
import json
import posixpath
import tarfile
from dataclasses import dataclass

from app.git_sync import snapshot_path
from app.models import GitSnapshot

MAX_PATH = 1024
MAX_FILES = 500
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024
_VARS_DIRS = ("group_vars", "host_vars")


class InventoryFileError(ValueError):
    """The path can't be used (the message is safe to show)."""


def check_path(path: str) -> str:
    """A path inside the repository: relative, plain segments, no '..'."""
    path = (path or "").strip().strip("/")
    parts = path.split("/")
    if (
        not path
        or len(path) > MAX_PATH
        or "\0" in path
        or any(part in ("", ".", "..") for part in parts)
    ):
        raise InventoryFileError(
            "Give a path inside the repository, such as inventory/hosts.ini or inventory/"
        )
    return path


@dataclass
class InventoryFiles:
    # [{"name": path in the repository, "text", "executable": the owner's execute bit in git}]
    files: list[dict]
    target: str  # what ansible-inventory reads: the file, or the directory
    digest: str  # changes when any of the files does


def _wanted(name: str, path: str, directory: bool) -> bool:
    if directory:
        return name.startswith(path + "/")
    base = posixpath.dirname(path)
    prefix = f"{base}/" if base else ""
    return name == path or any(name.startswith(f"{prefix}{d}/") for d in _VARS_DIRS)


def _read(tar: tarfile.TarFile, members: list[tarfile.TarInfo], what: str) -> list[dict]:
    files: list[dict] = []
    total = 0
    for member in sorted(members, key=lambda m: m.name):
        if len(files) >= MAX_FILES:
            raise InventoryFileError(f"{what}: more than {MAX_FILES} files")
        if member.size > MAX_FILE_BYTES:
            raise InventoryFileError(f"{member.name} is larger than 2 MiB")
        total += member.size
        if total > MAX_TOTAL_BYTES:
            raise InventoryFileError(f"{what}: more than 8 MiB of files")
        handle = tar.extractfile(member)
        try:
            text = handle.read().decode("utf-8") if handle else ""
        except UnicodeDecodeError:
            raise InventoryFileError(f"{member.name} is not UTF-8 text") from None
        files.append({"name": member.name, "text": text, "executable": bool(member.mode & 0o100)})
    return files


def _digest(files: list[dict]) -> str:
    material = [[f["name"], f["text"], f["executable"]] for f in files]
    return hashlib.sha256(json.dumps(material).encode()).hexdigest()


def read_script_files(snapshot: GitSnapshot, path: str) -> InventoryFiles:
    """The inventory script at `path` and every file in its directory and below;
    InventoryFileError if it isn't a script there, or there's too much."""
    path = check_path(path)
    commit = snapshot.commit[:12]
    with tarfile.open(snapshot_path(snapshot)) as tar:
        members = [m for m in tar.getmembers() if m.isfile()]
        script = next((m for m in members if m.name == path), None)
        if script is None:
            raise InventoryFileError(f"{path} is not a file in commit {commit}")
        base = posixpath.dirname(path)
        files = _read(
            tar, [m for m in members if not base or m.name.startswith(base + "/")], base or "/"
        )
    if not next(f for f in files if f["name"] == path)["text"].startswith("#!"):
        raise InventoryFileError(
            f"{path} doesn't start with a #! line naming its interpreter (#!/usr/bin/env python3)"
        )
    return InventoryFiles(files=files, target=path, digest=_digest(files))


def read_inventory_files(snapshot: GitSnapshot, path: str) -> InventoryFiles:
    """The inventory file at `path` in the commit (or every file under the directory at `path`)
    and the group_vars/ and host_vars/ beside it; InventoryFileError if there is none, or it
    is too large or not text."""
    path = check_path(path)
    commit = snapshot.commit[:12]
    with tarfile.open(snapshot_path(snapshot)) as tar:
        members = [m for m in tar.getmembers() if m.isfile()]
        names = {m.name for m in members}
        directory = path not in names
        if directory and not any(name.startswith(path + "/") for name in names):
            raise InventoryFileError(f"{path} is not in commit {commit}")
        files = _read(tar, [m for m in members if _wanted(m.name, path, directory)], path)
    return InventoryFiles(files=files, target=path, digest=_digest(files))
