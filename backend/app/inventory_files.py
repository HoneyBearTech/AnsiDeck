"""Inventory files from a git source (a dynamic inventory source of kind "git_file"): an INI or
YAML inventory file, or a directory of them, in a synced repository, read from the git source's
current commit when a refresh's job is built. The API sends the file (or the directory's files)
and the group_vars/ and host_vars/ beside it in the job, as text; the worker runs
ansible-inventory with only the yaml and ini plugins over them. Nothing else of the repository
reaches the refresh: not its ansible.cfg, plugins or scripts.

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
    files: list[dict]  # [{"name": path in the repository, "text"}]
    target: str  # what ansible-inventory reads: the file, or the directory
    digest: str  # changes when any of the files does


def _wanted(name: str, path: str, directory: bool) -> bool:
    if directory:
        return name.startswith(path + "/")
    base = posixpath.dirname(path)
    prefix = f"{base}/" if base else ""
    return name == path or any(name.startswith(f"{prefix}{d}/") for d in _VARS_DIRS)


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
        files: list[dict] = []
        total = 0
        for member in sorted(members, key=lambda m: m.name):
            if not _wanted(member.name, path, directory):
                continue
            if len(files) >= MAX_FILES:
                raise InventoryFileError(f"{path}: more than {MAX_FILES} files")
            if member.size > MAX_FILE_BYTES:
                raise InventoryFileError(f"{member.name} is larger than 2 MiB")
            total += member.size
            if total > MAX_TOTAL_BYTES:
                raise InventoryFileError(f"{path}: more than 8 MiB of files")
            handle = tar.extractfile(member)
            try:
                text = handle.read().decode("utf-8") if handle else ""
            except UnicodeDecodeError:
                raise InventoryFileError(f"{member.name} is not UTF-8 text") from None
            files.append({"name": member.name, "text": text})
    digest = hashlib.sha256(
        json.dumps([[f["name"], f["text"]] for f in files]).encode()
    ).hexdigest()
    return InventoryFiles(files=files, target=path, digest=digest)
