"""Syncs git sources: fetches a repository into a mirror, checks the tree, and turns each new
commit into an immutable snapshot (a tar of the tree that runs execute in) plus read-only
playbooks.

The remote and everything in it are untrusted, and git runs in the API container, so:
- the destination is resolved and refused unless public or allowlisted
  (GIT_ALLOWED_PRIVATE_HOSTS), then git connects to exactly that address (curl --resolve,
  ssh HostName), with no proxy and no redirects;
- only https and ssh (http to allowlisted private hosts; file:// only with the test-only
  GIT_ALLOW_LOCAL_SOURCES) via GIT_ALLOW_PROTOCOL, never ext:: or local paths;
- no system or user git config, no hooks (an empty --template, core.hooksPath=/dev/null),
  no credential helpers or prompts, fsck on every fetch, no submodules, no tags, depth 1;
- secrets (token, SSH key, known_hosts) live in a 0700 temp dir for one command, never in
  argv, the environment or the mirror's config, and are removed afterwards;
- every command has a timeout and the mirror a size limit (git has no client-side limit),
  enforced by killing its process group;
- a tree with a symlink pointing outside it, or over the size/file limits, never becomes
  current; submodules arrive as empty directories (with a warning).
"""

import base64
import contextlib
import fnmatch
import hashlib
import logging
import os
import posixpath
import re
import shlex
import shutil
import signal
import subprocess
import tarfile
import tempfile
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import yaml
from sqlalchemy import func, select, text, update
from sqlalchemy.orm import Session

from app import audit, metrics
from app.config import get_settings
from app.crypto import decrypt_secret
from app.db import get_engine, get_sessionmaker
from app.models import Credential, GitSnapshot, GitSource, Playbook, Run, RunStatus
from app.netguard import DestinationError, literal, resolve, vet
from app.scrub import _PlaybookLoader
from app.secret_store import SecretStoreError, explain, resolve_credential
from app.storage import git_mirror_path, git_snapshot_dir, playbook_path
from app.subprocess_env import clean_env

logger = logging.getLogger(__name__)

DEFAULT_GLOBS = ["*.yml", "*.yaml", "playbooks/*.yml", "playbooks/*.yaml"]
MAX_PLAYBOOK_BYTES = 1024 * 1024
MAX_ERROR_CHARS = 1000
PRUNE_AFTER_SECONDS = 600
SYNC_TOPIC = "git-sync"  # app.notify topic: a sync was requested
LOOP_SECONDS = 15
TEST_TIMEOUT_SECONDS = 30  # connection tests run inside a request
# pg_try_advisory_lock(int, int): this class id + the source id.
_LOCK_CLASS = 0x67697473  # "gits"
_resolve = resolve  # module-level, so tests can stub DNS

_HOST = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)
_USER = re.compile(r"^[A-Za-z0-9._][A-Za-z0-9._-]{0,63}$")
_SCP = re.compile(r"^(?:(?P<user>[^@/:]+)@)?(?P<host>[^@/:\[\]]+|\[[0-9A-Fa-f:.]+\]):(?P<path>.+)$")
_URL = re.compile(
    r"^(?P<scheme>https|http|ssh|file)://(?:(?P<user>[^@/]+)@)?"
    r"(?P<host>\[[0-9A-Fa-f:.]+\]|[^/:@]*)(?::(?P<port>\d{1,5}))?(?P<path>/.*)?$"
)


class SyncError(Exception):
    """A sync (or connection test) failed; the message is safe to show and store."""


@dataclass(frozen=True)
class Remote:
    kind: str  # https | http | ssh | file
    url: str  # as git gets it
    host: str  # lowercase, without brackets ("" for file)
    port: int
    user: str | None = None

    @property
    def host_key_alias(self) -> str:
        """The known_hosts name of an ssh remote (OpenSSH's own format for other ports)."""
        return self.host if self.port == 22 else f"[{self.host}]:{self.port}"


@dataclass
class Tree:
    """What sync checks before a commit may become current."""

    files: dict[str, tuple[str, int]]  # path -> (object id, size) of regular files
    file_count: int
    total_bytes: int
    warnings: list[str] = field(default_factory=list)


def _host(raw: str) -> str:
    host = raw[1:-1] if raw.startswith("[") and raw.endswith("]") else raw
    if literal(host) is None and not _HOST.match(host):
        raise SyncError(f"invalid host name in the URL: {raw!r}")
    return host.lower()


def parse_url(url: str, allow_local: bool | None = None) -> Remote:
    """A remote git may be pointed at, or SyncError. Only https://, ssh://, scp-style
    user@host:path (and http:// to allowlisted private hosts, checked on connect)."""
    if allow_local is None:
        allow_local = get_settings().git_allow_local_sources
    url = url.strip()
    if not url or len(url) > 500:
        raise SyncError("the URL must be 1 to 500 characters")
    if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in url):
        raise SyncError("the URL must not contain spaces or control characters")
    if url.startswith("-") or "::" in url.split("/", 1)[0]:
        raise SyncError("unsupported URL (use https://, ssh:// or user@host:path)")
    match = _URL.match(url)
    if match:
        scheme = match["scheme"]
        if scheme == "file":
            if not allow_local:
                raise SyncError("file:// sources are not allowed")
            return Remote("file", url, "", 0)
        if scheme in ("https", "http") and match["user"]:
            raise SyncError("put the user name and token in the source's settings, not the URL")
        host = _host(match["host"])
        default = {"https": 443, "http": 80, "ssh": 22}[scheme]
        port = int(match["port"]) if match["port"] else default
        if not 0 < port < 65536:
            raise SyncError("invalid port in the URL")
        path = match["path"] or ""
        if len(path) < 2 or path.startswith("/-"):
            raise SyncError("the URL needs a repository path")
        user = match["user"]
        if user is not None and not _USER.match(user):
            raise SyncError("invalid user name in the URL")
        return Remote(scheme, url, host, port, user)
    scp = _SCP.match(url)
    if scp and "://" not in url:
        user = scp["user"]
        if user is not None and not _USER.match(user):
            raise SyncError("invalid user name in the URL")
        if scp["path"].startswith("-"):
            raise SyncError("the URL needs a repository path")
        return Remote("ssh", url, _host(scp["host"]), 22, user)
    raise SyncError("unsupported URL (use https://, ssh:// or user@host:path)")


_BAD_REF = re.compile(r"(^[-/.]|/\.|\.\.|@\{|[\x00-\x20\x7f~^:?*\[\\]|//|/$|\.lock$|\.$|^@$)")


def check_branch(branch: str) -> str:
    branch = branch.strip()
    if not branch or len(branch) > 255 or _BAD_REF.search(branch):
        raise SyncError(f"invalid branch name: {branch!r}")
    return branch


def check_subdir(subdir: str | None) -> str | None:
    if subdir is None or not subdir.strip().strip("/"):
        return None
    subdir = subdir.strip().strip("/")
    parts = subdir.split("/")
    if (
        len(subdir) > 500
        or any(part in ("", ".", "..") or part.startswith("-") for part in parts)
        or any(ord(ch) < 32 for ch in subdir)
    ):
        raise SyncError(f"invalid subdirectory: {subdir!r}")
    return subdir


def check_globs(globs: list[str]) -> list[str]:
    cleaned = [g.strip() for g in globs if g.strip()]
    if not cleaned or len(cleaned) > 20:
        raise SyncError("give 1 to 20 playbook patterns")
    for glob in cleaned:
        if len(glob) > 200 or glob.startswith("/") or ".." in glob.split("/"):
            raise SyncError(f"invalid playbook pattern: {glob!r}")
    return cleaned


def glob_match(path: str, pattern: str) -> bool:
    """Path globbing: * and ? stay within one directory, ** spans any number of them."""
    return _segments_match(path.split("/"), pattern.split("/"))


def _segments_match(parts: list[str], pattern: list[str]) -> bool:
    if not pattern:
        return not parts
    if pattern[0] == "**":
        return any(_segments_match(parts[i:], pattern[1:]) for i in range(len(parts) + 1))
    return (
        bool(parts)
        and fnmatch.fnmatchcase(parts[0], pattern[0])
        and _segments_match(parts[1:], pattern[1:])
    )


def fingerprint(key_b64: str) -> str:
    digest = hashlib.sha256(base64.b64decode(key_b64)).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def destination(remote: Remote) -> tuple[str, bool]:
    """The address to connect to and whether it is private (allowlisted); SyncError if the
    destination is refused. Plain http only to allowlisted private hosts."""
    if remote.kind == "file":
        return "", True
    try:
        addresses = literal(remote.host) or _resolve(remote.host, remote.port)
        address, private = vet(
            remote.host, addresses, get_settings().git_allowlist, "GIT_ALLOWED_PRIVATE_HOSTS"
        )
    except DestinationError as exc:
        raise SyncError(str(exc)) from exc
    if remote.kind == "http" and not private:
        raise SyncError("public git servers must use https:// or ssh")
    return str(address), private


# --- running git -------------------------------------------------------------------------


@dataclass
class Auth:
    """What a command needs to reach the remote (decrypted, in memory only)."""

    token: str | None = None
    username: str | None = None
    ssh_key: str | None = None
    known_hosts: str | None = None


class _Session:
    """A private temp dir with the gitconfig, key and known_hosts for one source's commands,
    and the environment that points git at them. Removed on exit."""

    def __init__(self, remote: Remote, address: str, auth: Auth) -> None:
        self.remote, self.address, self.auth = remote, address, auth

    def __enter__(self) -> "_Session":
        self.dir = Path(tempfile.mkdtemp(prefix="ansideck-git-"))
        os.chmod(self.dir, 0o700)
        # "none": commands that only read the mirror get no transport at all.
        allowed = "" if self.remote.kind == "none" else self.remote.kind
        config = [
            "[protocol]\n\tallow = never\n",
            f'[protocol "{allowed or "none"}"]\n\tallow = always\n',
            "[core]\n\thooksPath = /dev/null\n\tfsmonitor = false\n\tsymlinks = true\n",
            '[credential]\n\thelper = ""\n',
            "[transfer]\n\tfsckObjects = true\n",
            "[fetch]\n\tfsckObjects = true\n",
            "[gc]\n\tauto = 0\n",
            "[maintenance]\n\tauto = false\n",
            "[tar]\n\tumask = 0022\n",
            "[init]\n\tdefaultBranch = main\n",
            "[http]\n\tfollowRedirects = false\n\tsslVerify = true\n\tproxy = \n"
            "\tlowSpeedLimit = 1024\n\tlowSpeedTime = 60\n",
        ]
        if self.remote.kind in ("https", "http"):
            target = f"[{self.address}]" if ":" in self.address else self.address
            config.append(
                f"[http]\n\tcurloptResolve = {self.remote.host}:{self.remote.port}:{target}\n"
            )
            if self.auth.token:
                pair = f"{self.auth.username or 'git'}:{self.auth.token}".encode()
                header = "Authorization: Basic " + base64.b64encode(pair).decode()
                config.append(f"[http]\n\textraHeader = {header}\n")
        self.gitconfig = self.dir / "gitconfig"
        self._write(self.gitconfig, "".join(config))
        self.env = clean_env(
            {
                "HOME": str(self.dir),
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": str(self.gitconfig),
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_ASKPASS": "/bin/false",
                "SSH_ASKPASS": "/bin/false",
                "GIT_ALLOW_PROTOCOL": allowed,
                "GIT_PROTOCOL_FROM_USER": "0",
                "GIT_NO_LAZY_FETCH": "1",
                "GIT_NO_REPLACE_OBJECTS": "1",
                "GIT_OPTIONAL_LOCKS": "0",
                "LC_ALL": "C",
            }
        )
        for proxy in ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy"):
            self.env.pop(proxy, None)  # git, like notifications, never goes through a proxy
        self.env.pop("no_proxy", None)
        if self.remote.kind == "ssh":
            self.env["GIT_SSH_VARIANT"] = "ssh"
            self.env["GIT_SSH_COMMAND"] = shlex.join(self.ssh_command())
        return self

    def _write(self, path: Path, content: str) -> None:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(content)

    def ssh_options(self) -> list[str]:
        known = self.dir / "known_hosts"
        if not known.exists():
            self._write(known, self.auth.known_hosts or "")
        options = [
            "-F", "/dev/null",
            "-o", "BatchMode=yes",
            "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={known}",
            "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "UpdateHostKeys=no",
            "-o", f"HostKeyAlias={self.remote.host_key_alias}",
            "-o", f"HostName={self.address}",
            "-o", f"Port={self.remote.port}",
            "-o", "ProxyCommand=none",
            "-o", "ProxyJump=none",
            "-o", "ControlMaster=no",
            "-o", "ControlPath=none",
            "-o", "PermitLocalCommand=no",
            "-o", "ForwardAgent=no",
            "-o", "ForwardX11=no",
            "-o", "ClearAllForwardings=yes",
            "-o", "RequestTTY=no",
            "-o", "IdentityAgent=none",
            "-o", "ConnectTimeout=15",
            "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=4",
        ]  # fmt: skip
        if self.auth.ssh_key:
            key = self.dir / "key"
            if not key.exists():
                self._write(key, self.auth.ssh_key.rstrip("\n") + "\n")
            options += ["-i", str(key), "-o", "IdentitiesOnly=yes"]
        return options

    def ssh_command(self) -> list[str]:
        return ["ssh", *self.ssh_options()]

    def __exit__(self, *exc) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)


def _dir_bytes(path: Path) -> int:
    total = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            with contextlib.suppress(OSError):
                total += os.lstat(os.path.join(root, name)).st_size
    return total


def _redact(message: str, auth: Auth) -> str:
    for secret in (auth.token,):
        if secret:
            message = message.replace(secret, "[REDACTED]")
    return message.strip()[-MAX_ERROR_CHARS:]


def _run(
    cmd: list[str],
    session: _Session,
    *,
    watch: Path | None = None,
    stdin: bytes | None = None,
    stdout_path: Path | None = None,
    max_output: int | None = None,
    timeout: int | None = None,
) -> bytes:
    """Runs one command in its own process group, killed at the sync timeout, when the
    watched directory grows past the mirror limit, or when its output passes max_output.
    Returns stdout (unless written to stdout_path); SyncError on failure."""
    settings = get_settings()
    limit = settings.git_max_repo_mb * 1024 * 1024
    killed: list[str] = []
    out_handle = open(stdout_path, "wb") if stdout_path else None  # noqa: SIM115
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
        stdout=out_handle or subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        env=session.env,
    )

    def kill(reason: str) -> None:
        killed.append(reason)
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)

    seconds = timeout or settings.git_sync_timeout_seconds
    timer = threading.Timer(seconds, kill, [f"{cmd[0]} took longer than {seconds} s"])
    timer.start()
    stop = threading.Event()

    def watchdog() -> None:
        while not stop.wait(0.5):
            if watch is not None and _dir_bytes(watch) > limit:
                kill(f"the repository is larger than {settings.git_max_repo_mb} MB")
                return
            if stdout_path is not None and max_output and stdout_path.stat().st_size > max_output:
                kill("the snapshot is larger than the limit")
                return

    watcher = threading.Thread(target=watchdog, daemon=True)
    watcher.start()
    try:
        stdout, stderr = proc.communicate(stdin)
    finally:
        timer.cancel()
        stop.set()
        watcher.join()
        if out_handle:
            out_handle.close()
    if killed:
        raise SyncError(killed[0])
    if proc.returncode != 0:
        message = stderr.decode(errors="replace") or f"{cmd[0]} exited with {proc.returncode}"
        raise SyncError(_redact(message, session.auth))
    if max_output is not None and stdout is not None and len(stdout) > max_output:
        raise SyncError("git returned more data than expected")
    return stdout or b""


def _git(mirror: Path, *args: str) -> list[str]:
    return ["git", f"--git-dir={mirror}", *args]


# --- talking to the remote ---------------------------------------------------------------


def ls_remote(remote: Remote, auth: Auth, branch: str) -> dict:
    """The remote's default branch and whether `branch` exists (the connection test)."""
    address, _ = destination(remote)
    with _Session(remote, address, auth) as session:
        out = _run(
            ["git", "ls-remote", "--symref", "--end-of-options", remote.url, "HEAD",
             f"refs/heads/{branch}"],
            session,
            max_output=1024 * 1024,
            timeout=TEST_TIMEOUT_SECONDS,
        )  # fmt: skip
    default = None
    found = False
    for line in out.decode(errors="replace").splitlines():
        if line.startswith("ref: ") and line.endswith("\tHEAD"):
            default = line[5:].split("\t", 1)[0].removeprefix("refs/heads/")
        elif line.endswith(f"\trefs/heads/{branch}"):
            found = True
    return {"default_branch": default, "branch_exists": found}


def keyscan(remote: Remote) -> list[dict]:
    """The server's SSH host keys (type, key, SHA256 fingerprint), keyed by the remote's
    host name, for an admin to confirm."""
    if remote.kind != "ssh":
        raise SyncError("only ssh sources have host keys")
    address, _ = destination(remote)
    with _Session(remote, address, Auth()) as session:
        out = _run(
            ["ssh-keyscan", "-T", "10", "-p", str(remote.port), "-t", "rsa,ecdsa,ed25519",
             "--", address],
            session,
            max_output=64 * 1024,
            timeout=TEST_TIMEOUT_SECONDS,
        )  # fmt: skip
    keys = []
    for line in out.decode(errors="replace").splitlines():
        parts = line.split()
        if len(parts) != 3 or line.startswith("#"):
            continue
        _, key_type, blob = parts
        try:
            keys.append({"type": key_type, "key": blob, "fingerprint": fingerprint(blob)})
        except ValueError:
            continue
    if not keys:
        raise SyncError(f"no SSH host key received from {remote.host}")
    return keys


def known_hosts_line(remote: Remote, key_type: str, blob: str) -> str:
    return f"{remote.host_key_alias} {key_type} {blob}"


def parse_known_hosts(remote: Remote, pasted: str) -> str:
    """Pasted known_hosts lines for the remote's host, rewritten to its alias."""
    lines = []
    for raw in pasted.splitlines():
        parts = raw.split()
        if len(parts) < 3 or raw.lstrip().startswith(("#", "@", "|")):
            continue
        names, key_type, blob = parts[0], parts[1], parts[2]
        try:
            base64.b64decode(blob, validate=True)
        except ValueError:
            continue
        hosts = {name.lower() for name in names.split(",")}
        if remote.host_key_alias.lower() in hosts or remote.host in hosts:
            lines.append(known_hosts_line(remote, key_type, blob))
    if not lines:
        raise SyncError(f"no key for {remote.host_key_alias} in what was pasted")
    return "\n".join(lines) + "\n"


def fetch(remote: Remote, auth: Auth, mirror: Path, branch: str) -> str:
    """Updates the mirror's copy of `branch` (depth 1); returns its commit id."""
    address, _ = destination(remote)
    url_file = mirror / "ansideck-url"
    if mirror.exists() and (not url_file.exists() or url_file.read_text() != remote.url):
        shutil.rmtree(mirror)  # another URL: start over rather than mix histories
    with _Session(remote, address, auth) as session:
        if not mirror.exists():
            mirror.parent.mkdir(parents=True, exist_ok=True)
            _run(["git", "init", "--quiet", "--bare", "--template=", str(mirror)], session)
            (mirror / "info").mkdir(exist_ok=True)
            # Runs get the tree as a checkout would: no export-subst / export-ignore.
            (mirror / "info" / "attributes").write_text("* -export-subst -export-ignore\n")
            url_file.write_text(remote.url)
        try:
            _run(
                _git(mirror, "fetch", "--quiet", "--depth=1", "--no-tags",
                     "--no-recurse-submodules", "--no-write-fetch-head", "--end-of-options",
                     remote.url, f"+refs/heads/{branch}:refs/heads/{branch}"),
                session,
                watch=mirror,
            )  # fmt: skip
        except SyncError:
            if _dir_bytes(mirror) > get_settings().git_max_repo_mb * 1024 * 1024:
                shutil.rmtree(mirror, ignore_errors=True)
            raise
        # The watchdog samples while git runs; a fast fetch can finish between samples.
        if _dir_bytes(mirror) > get_settings().git_max_repo_mb * 1024 * 1024:
            shutil.rmtree(mirror, ignore_errors=True)
            raise SyncError(f"the repository is larger than {get_settings().git_max_repo_mb} MB")
        commit = _run(_git(mirror, "rev-parse", "--verify", f"refs/heads/{branch}^{{commit}}"),
                      session).decode().strip()  # fmt: skip
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit):
        raise SyncError("unexpected commit id from git")
    return commit


# --- checking a commit -------------------------------------------------------------------


def _local() -> _Session:
    """A session for commands that only read the mirror (no transport allowed)."""
    return _Session(Remote("none", "", "", 0), "", Auth())


def _cat(session: _Session, mirror: Path, object_ids: list[str]) -> dict[str, bytes]:
    if not object_ids:
        return {}
    out = _run(
        _git(mirror, "cat-file", "--batch"),
        session,
        stdin=("\n".join(object_ids) + "\n").encode(),
    )
    contents, pos = {}, 0
    for oid in object_ids:
        header_end = out.index(b"\n", pos)
        header = out[pos:header_end].split()
        if len(header) != 3:
            raise SyncError(f"git could not read object {oid}")
        size = int(header[2])
        contents[oid] = out[header_end + 1 : header_end + 1 + size]
        pos = header_end + 1 + size + 1
    return contents


def commit_info(mirror: Path, commit: str) -> dict:
    with _local() as session:
        out = _run(_git(mirror, "show", "-s", "--format=%s%x00%an%x00%cI", commit), session)
    subject, author, when = (out.decode(errors="replace").rstrip("\n").split("\0") + ["", "", ""])[
        :3
    ]
    return {
        "commit_subject": subject[:255],
        "commit_author": author[:255],
        "committed_at": datetime.fromisoformat(when) if when else None,
    }


def _inside(link_path: str, target: str) -> bool:
    """Whether a symlink at link_path pointing at target stays inside the tree. `..` may
    only lead the target (a later one could climb out through another symlink)."""
    if target.startswith("/") or "\0" in target:
        return False
    parts = [p for p in target.split("/") if p not in ("", ".")]
    seen_name = False
    for part in parts:
        if part == "..":
            if seen_name:
                return False
        else:
            seen_name = True
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(link_path), target))
    return resolved != ".." and not resolved.startswith("../") and not resolved.startswith("/")


def inspect_tree(mirror: Path, commit: str, subdir: str | None) -> Tree:
    """The commit's tree (or subdir) as runs would get it, or SyncError when it may not
    become current."""
    settings = get_settings()
    treeish = f"{commit}:{subdir}" if subdir else f"{commit}^{{tree}}"
    with _local() as session:
        try:
            kind = _run(_git(mirror, "cat-file", "-t", treeish), session).decode().strip()
        except SyncError as exc:
            raise SyncError(f"{subdir!r} does not exist in the repository") from exc
        if kind != "tree":
            raise SyncError(f"{subdir!r} is not a directory in the repository")
        out = _run(_git(mirror, "ls-tree", "-r", "-z", "--long", treeish), session)
        files: dict[str, tuple[str, int]] = {}
        links: dict[str, str] = {}
        warnings: list[str] = []
        total = count = 0
        for entry in out.split(b"\0"):
            if not entry:
                continue
            meta, _, raw_path = entry.partition(b"\t")
            mode, kind, oid, size = meta.decode().split()
            path = raw_path.decode("utf-8", errors="surrogateescape")
            count += 1
            if kind == "commit":
                warnings.append(f"submodule {path} is not fetched (it is an empty directory)")
                continue
            if mode == "120000":
                links[path] = oid
            else:
                files[path] = (oid, int(size))
            total += int(size) if size != "-" else 0
        if count > settings.git_max_files:
            raise SyncError(f"the repository has more than {settings.git_max_files} files")
        if total > settings.git_max_snapshot_mb * 1024 * 1024:
            raise SyncError(f"the files add up to more than {settings.git_max_snapshot_mb} MB")
        targets = _cat(session, mirror, list(links.values()))
        for path, oid in links.items():
            target = targets[oid].decode("utf-8", errors="surrogateescape")
            if not _inside(path, target):
                raise SyncError(f"symlink {path} points outside the repository ({target})")
    for requirements in ("requirements.yml", "roles/requirements.yml",
                         "collections/requirements.yml"):  # fmt: skip
        if requirements in files:
            warnings.append(
                f"{requirements} is not installed automatically: install its roles and "
                "collections on the Galaxy page"
            )
    return Tree(files, count, total, warnings)


def _is_playbook(content: bytes) -> bool:
    try:
        data = yaml.load(content.decode("utf-8"), Loader=_PlaybookLoader)  # noqa: S506
    except (yaml.YAMLError, UnicodeDecodeError, RecursionError):
        return False
    return (
        isinstance(data, list)
        and bool(data)
        and all(
            isinstance(play, dict)
            and any(
                k in play for k in ("hosts", "import_playbook", "ansible.builtin.import_playbook")
            )
            for play in data
        )
    )


def discover_playbooks(
    mirror: Path, tree: Tree, globs: list[str]
) -> tuple[dict[str, str], list[str]]:
    """{repo path: content} of the files that match a pattern and parse as a playbook."""
    settings = get_settings()
    warnings: list[str] = []
    candidates = sorted(
        path
        for path, (_, size) in tree.files.items()
        if any(glob_match(path, g) for g in globs) and size <= MAX_PLAYBOOK_BYTES
    )
    if len(candidates) > settings.git_max_playbooks:
        warnings.append(
            f"only the first {settings.git_max_playbooks} of {len(candidates)} matching files "
            "were read"
        )
        candidates = candidates[: settings.git_max_playbooks]
    with _local() as session:
        contents = _cat(session, mirror, [tree.files[p][0] for p in candidates])
    found = {}
    for path in candidates:
        content = contents[tree.files[path][0]]
        if len(path) > 255:
            warnings.append(f"{path[:60]}… is skipped: the path is longer than 255 characters")
        elif _is_playbook(content):
            found[path] = content.decode("utf-8")
    return found, warnings


def build_snapshot(mirror: Path, commit: str, subdir: str | None, tree: Tree, dest: Path) -> str:
    """Writes the tree as a tar to dest (atomically); returns its sha256."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(".partial")
    treeish = f"{commit}:{subdir}" if subdir else commit
    limit = tree.total_bytes + tree.file_count * 2048 + 1024 * 1024
    with _local() as session:
        try:
            _run(
                _git(mirror, "archive", "--format=tar", treeish),
                session,
                stdout_path=tmp,
                max_output=limit,
            )
        except SyncError:
            tmp.unlink(missing_ok=True)
            raise
    digest = hashlib.sha256()
    with open(tmp, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    os.chmod(tmp, 0o640)
    os.replace(tmp, dest)
    return digest.hexdigest()


# --- syncing a source --------------------------------------------------------------------


def remote_for(source: GitSource) -> Remote:
    return parse_url(source.url)


def auth_for(db: Session, source: GitSource) -> Auth:
    auth = Auth(known_hosts=source.ssh_known_hosts)
    if source.auth_kind == "https_token" and source.encrypted_token:
        auth.token = decrypt_secret(source.encrypted_token).decode()
        auth.username = source.https_username
    elif source.auth_kind == "ssh_key" and source.credential_id is not None:
        credential = db.get(Credential, source.credential_id)
        if credential is None or credential.project_id != source.project_id:
            raise SyncError("the source's SSH key is gone or in another project")
        try:
            auth.ssh_key = resolve_credential(credential)
        except SecretStoreError as exc:
            raise SyncError(
                f"could not read the deploy key '{credential.name}' from the secret store: "
                f"{explain(exc.kind)}"
            ) from None
    return auth


def _write_display_copy(playbook_id: int, content: str) -> None:
    path = playbook_path(playbook_id)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(content)
    os.replace(tmp, path)


def _apply(db: Session, source: GitSource, snapshot: GitSnapshot, found: dict[str, str]) -> dict:
    """Points the source at the snapshot and brings its playbooks in line (the caller holds
    the source's row lock and commits). Display copies are rewritten only when the commit
    changed or a playbook (re)appeared."""
    changed = source.current_snapshot_id != snapshot.id
    now = datetime.now(UTC)
    if source.current_snapshot_id not in (None, snapshot.id):
        db.execute(
            update(GitSnapshot)
            .where(GitSnapshot.id == source.current_snapshot_id)
            .values(superseded_at=func.now())
        )
    source.current_snapshot_id = snapshot.id
    existing = {
        p.repo_path: p for p in db.scalars(select(Playbook).where(Playbook.source_id == source.id))
    }
    added, revived, removed = [], [], []
    written: list[tuple[int, str]] = []
    for path, content in found.items():
        playbook = existing.get(path)
        if playbook is None:
            playbook = Playbook(
                name=path, project_id=source.project_id, source_id=source.id, repo_path=path
            )
            db.add(playbook)
            db.flush()
            added.append(path)
        elif playbook.missing_at is not None:
            playbook.missing_at = None
            revived.append(path)
        elif not changed:
            continue
        playbook.updated_at = now
        written.append((playbook.id, content))
    for path, playbook in existing.items():
        if path not in found and playbook.missing_at is None:
            playbook.missing_at = now
            removed.append(path)
    for playbook_id, content in written:
        _write_display_copy(playbook_id, content)
    return {"added": added, "revived": revived, "removed": removed}


@contextlib.contextmanager
def _source_lock(source_id: int) -> Iterator[bool]:
    """A session-level advisory lock on its own connection: one sync per source at a time,
    released even if this process dies."""
    with get_engine().connect() as conn:
        held = conn.execute(
            text("SELECT pg_try_advisory_lock(:a, :b)"), {"a": _LOCK_CLASS, "b": source_id}
        ).scalar()
        conn.commit()
        try:
            yield bool(held)
        finally:
            if held:
                conn.execute(
                    text("SELECT pg_advisory_unlock(:a, :b)"), {"a": _LOCK_CLASS, "b": source_id}
                )
                conn.commit()


def sync_source(source_id: int) -> str:
    """Syncs one source; returns "ok", "unchanged", "failed" or "busy"."""
    started = time.monotonic()
    with _source_lock(source_id) as held:
        if not held:
            return "busy"
        outcome = _sync_locked(source_id)
    metrics.git_sync_finished(outcome, time.monotonic() - started)
    return outcome


def _sync_locked(source_id: int) -> str:
    db = get_sessionmaker()()
    try:
        source = db.get(GitSource, source_id)
        if source is None:
            return "failed"
        previous_status = source.last_sync_status
        source.last_sync_started_at = func.now()
        source.last_sync_status = "running"
        source.sync_requested_at = None
        db.commit()
        try:
            remote = remote_for(source)
            if remote.kind == "ssh" and not source.ssh_known_hosts:
                raise SyncError("trust the server's SSH host key first (Test connection)")
            branch = check_branch(source.branch)
            subdir = check_subdir(source.subdir)
            mirror = git_mirror_path(source.id)
            commit = fetch(remote, auth_for(db, source), mirror, branch)
            snapshot = db.scalars(
                select(GitSnapshot).where(
                    GitSnapshot.source_id == source.id, GitSnapshot.commit == commit
                )
            ).first()
            tree = inspect_tree(mirror, commit, subdir)
            found, discover_warnings = discover_playbooks(
                mirror, tree, source.playbook_globs or DEFAULT_GLOBS
            )
            tar = git_snapshot_dir(source.id) / f"{commit}.tar"
            if snapshot is None or not tar.exists():
                sha256 = build_snapshot(mirror, commit, subdir, tree, tar)
                if snapshot is None:
                    snapshot = GitSnapshot(
                        source_id=source.id,
                        commit=commit,
                        size_bytes=tar.stat().st_size,
                        file_count=tree.file_count,
                        sha256=sha256,
                        warnings=tree.warnings + discover_warnings,
                        **commit_info(mirror, commit),
                    )
                    db.add(snapshot)
                else:
                    snapshot.sha256, snapshot.size_bytes = sha256, tar.stat().st_size
            snapshot.superseded_at = None
        except SyncError as exc:
            return _failed(db, source_id, str(exc), previous_status)
        except Exception:  # noqa: BLE001 - recorded; never leaks details that might hold secrets
            logger.exception("git sync of source %s failed", source_id)
            return _failed(db, source_id, "unexpected error (see the server log)", previous_status)

        source = db.scalars(
            select(GitSource).where(GitSource.id == source_id).with_for_update()
        ).first()
        if source is None:
            db.rollback()
            return "failed"
        db.flush()
        changed = source.current_snapshot_id != snapshot.id
        before = (
            db.get(GitSnapshot, source.current_snapshot_id) if source.current_snapshot_id else None
        )
        changes = _apply(db, source, snapshot, found)
        source.last_sync_status = "ok"
        source.last_sync_error = None
        source.last_sync_finished_at = func.now()
        db.commit()
        if changed or any(changes.values()):
            audit.record(
                db,
                "git_source.sync",
                actor_username="(git sync)",
                target_type="git_source",
                target_id=source_id,
                target_name=source.name,
                project_id=source.project_id,
                detail={
                    "from": before.commit if before else None,
                    "to": snapshot.commit,
                    "added": len(changes["added"]),
                    "removed": len(changes["removed"]),
                    "revived": len(changes["revived"]),
                },
            )
            return "ok"
        return "unchanged"
    finally:
        db.close()


def _failed(db: Session, source_id: int, message: str, previous_status: str | None) -> str:
    db.rollback()
    source = db.get(GitSource, source_id)
    if source is None:
        return "failed"
    source.last_sync_status = "failed"
    source.last_sync_error = message[:MAX_ERROR_CHARS]
    source.last_sync_finished_at = func.now()
    db.commit()
    if previous_status != "failed":  # once per episode, not every poll
        mismatch = "host key" in message.lower() and "verification failed" in message.lower()
        audit.record(
            db,
            "git_source.host_key_mismatch" if mismatch else "git_source.sync",
            outcome="failure",
            actor_username="(git sync)",
            target_type="git_source",
            target_id=source_id,
            target_name=source.name,
            project_id=source.project_id,
            detail={"reason": "host key" if mismatch else "sync failed"},
        )
    return "failed"


def due_sources(db: Session) -> list[int]:
    """Sources to sync now: requested, or enabled and due by their interval. SSH sources
    without a trusted host key only when someone asks (they would fail every time)."""
    interval = func.make_interval(0, 0, 0, 0, 0, 0, GitSource.auto_sync_seconds)
    rows = db.execute(
        select(GitSource.id, GitSource.sync_requested_at, GitSource.url, GitSource.ssh_known_hosts)
        .where(GitSource.enabled.is_(True))
        .where(
            (GitSource.sync_requested_at.is_not(None))
            | (
                (GitSource.auto_sync_seconds > 0)
                & (
                    GitSource.last_sync_started_at.is_(None)
                    | (GitSource.last_sync_started_at < func.now() - interval)
                )
            )
        )
        .order_by(GitSource.sync_requested_at.desc().nulls_last(), GitSource.id)
    ).all()
    due = []
    for source_id, requested, url, known_hosts in rows:
        ssh = not url.startswith(("https://", "http://", "file://"))
        if requested is None and ssh and not known_hosts:
            continue
        due.append(source_id)
    return due


def prune_snapshots(db: Session) -> int:
    """Deletes snapshots superseded a while ago that no source points at and no queued or
    running run is pinned to (their tars too)."""
    pinned = select(Run.git_snapshot_id).where(
        Run.status.in_((RunStatus.QUEUED.value, RunStatus.RUNNING.value)),
        Run.git_snapshot_id.is_not(None),
    )
    current = select(GitSource.current_snapshot_id).where(
        GitSource.current_snapshot_id.is_not(None)
    )
    stale = db.execute(
        select(GitSnapshot.id, GitSnapshot.source_id, GitSnapshot.commit).where(
            GitSnapshot.superseded_at
            < func.now() - func.make_interval(0, 0, 0, 0, 0, 0, PRUNE_AFTER_SECONDS),
            GitSnapshot.id.not_in(pinned),
            GitSnapshot.id.not_in(current),
        )
    ).all()
    for snapshot_id, source_id, commit in stale:
        db.execute(GitSnapshot.__table__.delete().where(GitSnapshot.id == snapshot_id))
        (git_snapshot_dir(source_id) / f"{commit}.tar").unlink(missing_ok=True)
    db.commit()
    return len(stale)


def snapshot_path(snapshot: GitSnapshot) -> Path:
    return git_snapshot_dir(snapshot.source_id) / f"{snapshot.commit}.tar"


def read_member(snapshot: GitSnapshot, path: str, max_bytes: int = MAX_PLAYBOOK_BYTES) -> str:
    """A regular file's text from a snapshot (a run's playbook), or SyncError."""
    with tarfile.open(snapshot_path(snapshot)) as tar:
        try:
            member = tar.getmember(path)
        except KeyError as exc:
            raise SyncError(f"{path} is not in commit {snapshot.commit[:12]}") from exc
        if not member.isfile() or member.size > max_bytes:
            raise SyncError(f"{path} is not a playbook file")
        handle = tar.extractfile(member)
        assert handle is not None
        try:
            return handle.read().decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SyncError(f"{path} is not UTF-8 text") from exc


# Where a repository keeps variables (which may hold vaulted secrets the run's output must not
# show): inventory-style group_vars/host_vars anywhere, vars/, and roles' vars and defaults.
_VARS_FILE = re.compile(
    r"(^|/)(group_vars|host_vars)/.+|(^|/)vars/[^/]+$|^roles/[^/]+/(vars|defaults)/.+"
)
MAX_VARS_FILE_BYTES = 256 * 1024
MAX_VARS_TOTAL_BYTES = 4 * 1024 * 1024


def vars_texts(snapshot: GitSnapshot) -> list[str]:
    """The text of the snapshot's variable files (bounded), for the scrubber to find secrets
    in: vaulted values and values under secret-looking keys."""
    texts: list[str] = []
    total = 0
    with tarfile.open(snapshot_path(snapshot)) as tar:
        for member in tar:
            if not member.isfile() or member.size > MAX_VARS_FILE_BYTES:
                continue
            if not _VARS_FILE.search(member.name):
                continue
            if total + member.size > MAX_VARS_TOTAL_BYTES:
                break
            handle = tar.extractfile(member)
            if handle is None:
                continue
            try:
                texts.append(handle.read().decode("utf-8"))
            except UnicodeDecodeError:
                continue
            total += member.size
    return texts


def remove_files(source_id: int, playbook_ids: list[int]) -> None:
    """After a source was deleted: its mirror, snapshots and playbook display copies."""
    shutil.rmtree(git_mirror_path(source_id), ignore_errors=True)
    shutil.rmtree(git_snapshot_dir(source_id), ignore_errors=True)
    for playbook_id in playbook_ids:
        playbook_path(playbook_id).unlink(missing_ok=True)
