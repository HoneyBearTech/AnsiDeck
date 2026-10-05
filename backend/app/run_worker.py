"""Child-process entry point that actually runs ansible-runner (python -m app.run_worker).

ansible-runner seeds the playbook's environment from os.environ with no way to opt out,
so run_executor spawns this module with an allowlisted environment instead of running
ansible-runner in the app process. Deliberately imports nothing from app.* — in
particular not app.config, which would load the app's secrets.

Protocol: one JSON job line on stdin: ansible_runner.run kwargs plus "event_fd", "files"
({"playbook": text, "inventory": text}), "prefix" (of the private data dir's name),
"own_home" (isolated runs: use, and check, the slot user's home; see app.run_isolation) and
"project" (a run of a playbook synced from git: {"playbook": its path in the repository}; the
repository itself, a tar, follows the job line on stdin and is unpacked as the project).
One JSON line per message on the inherited event_fd: {"type": "refused", "reason": ...} alone
if the run can't be set up (e.g. its repository won't unpack), else {"type": "started",
"private_data_dir": ...} first, then {"type": "event", "event": {...}} for each
ansible-runner event, then a final {"type": "result", "status": ..., "rc": ...}.
SIGTERM is turned into a clean ansible-runner cancel by ansible-runner itself (it
installs the handler when running in the main thread).

This process creates the run's files itself: when runs are isolated it runs as the slot's
own user (app.run_isolation), and the worker never touches a run's files.

`python -m app.run_worker --sweep DIR...` is the cleanup after an isolated run, executed
as the slot's user: it kills every process of that user, makes its home private again and
deletes the user's files under the given directories. It exits with HOME_NOT_CLEAN if
another user's directory is left in the home (the worker then replaces the home).
"""

import contextlib
import json
import os
import pwd
import re
import shutil
import signal
import stat
import sys
import tempfile
import time
from pathlib import Path

# Same value as app.run_isolation.RUN_UID_BASE: --sweep refuses to run as anyone else, since
# kill(-1) as root (or as a developer) would kill far more than one run.
_RUN_UID_BASE = 20000
_SWEEP_KILL_ROUNDS = 100
HOME_NOT_CLEAN = 3  # app.run_executor.sweep() acts on it


MAX_PROJECT_ENTRIES = 50_000
MAX_PROJECT_BYTES = 1024 * 1024 * 1024  # the API caps snapshots far lower; this guards the child
_SAFE_TARFILE = (3, 12, 11)  # tarfile's "data" filter has the 2025 path-escape fixes


def unpack_project(stream, project: Path) -> None:
    """Unpacks a repository tar into `project` with tarfile's "data" filter: nothing outside
    it (no "..", absolute paths, links pointing out, devices), no setuid bits, and limits on
    entries and bytes. Raises on anything refused."""
    if sys.version_info < _SAFE_TARFILE:
        raise RuntimeError("Python 3.12.11 or later is needed to unpack repositories safely")
    import tarfile

    counted = {"entries": 0, "bytes": 0}

    def guarded(member, path):
        counted["entries"] += 1
        counted["bytes"] += member.size
        if counted["entries"] > MAX_PROJECT_ENTRIES or counted["bytes"] > MAX_PROJECT_BYTES:
            raise RuntimeError("the repository is too large to unpack")
        return tarfile.data_filter(member, path)

    with tarfile.open(fileobj=stream, mode="r|") as tar:
        tar.extractall(project, filter=guarded)  # noqa: S202 - guarded by a data filter
    while stream.read(65536):  # the archive's padding: the sender is still writing it
        pass


def project_playbook(project: Path, path: str) -> str:
    """The repository playbook a run executes, which must be a file inside the project."""
    parts = path.split("/")
    if not path or path.startswith("/") or ".." in parts or "\0" in path:
        raise RuntimeError(f"invalid playbook path: {path!r}")
    real = os.path.realpath(project / path)
    if not real.startswith(os.path.realpath(project) + os.sep) or not os.path.isfile(real):
        raise RuntimeError(f"{path} is not a file in the repository")
    return path


def _search_path(project: Path, variable: str, keys: tuple[str, ...], default: str) -> str:
    """`variable` (roles or collections path) with the repository's own entries first: its
    roles/ or collections/, then those its ansible.cfg names inside the repository. The
    environment overrides ansible.cfg, so they must be merged here."""
    import configparser

    entries = [project / default]
    cfg = project / "ansible.cfg"
    if cfg.is_file():
        parser = configparser.ConfigParser(interpolation=None, strict=False)
        with contextlib.suppress(configparser.Error, UnicodeDecodeError):
            parser.read(cfg, encoding="utf-8")
        inside = os.path.realpath(project) + os.sep
        for key in keys:
            for raw in parser.get("defaults", key, fallback="").split(os.pathsep):
                entry = raw.strip()
                if not entry or entry.startswith("~"):
                    continue
                path = Path(os.path.realpath(project / entry))
                if str(path).startswith(inside) and path not in entries:
                    entries.append(path)
    existing = os.environ.get(variable, "")
    return os.pathsep.join([str(e) for e in entries] + ([existing] if existing else []))


def prepare(job: dict) -> str:
    """Creates the run's private data dir (0700) with its playbook and inventory, and gives
    ansible a home of its own in it: its SSH ControlPersist sockets (~/.ansible/cp) would
    otherwise be shared, and a run could ride another run's authenticated connection to the
    same user@host. Returns the private data dir."""
    files = job.pop("files")
    own_home = job.pop("own_home", False)
    repository = job.pop("project", None)
    # Short paths: SSH's control and agent sockets live in here (104-108 byte limit).
    base = "/tmp" if os.path.isdir("/tmp") else None  # noqa: S108 - short socket paths; mkdtemp is private
    pdd = Path(tempfile.mkdtemp(prefix=job.pop("prefix", "ansideck-run-"), dir=base))
    project = pdd / "project"
    project.mkdir()
    if repository is not None:
        try:
            unpack_project(sys.stdin.buffer, project)
            playbook = project_playbook(project, repository["playbook"])
        except BaseException:
            shutil.rmtree(pdd, ignore_errors=True)
            raise
        os.environ["ANSIBLE_ROLES_PATH"] = _search_path(
            project, "ANSIBLE_ROLES_PATH", ("roles_path",), "roles"
        )
        os.environ["ANSIBLE_COLLECTIONS_PATH"] = _search_path(
            project,
            "ANSIBLE_COLLECTIONS_PATH",
            ("collections_path", "collections_paths"),
            "collections",
        )
    else:
        playbook = "playbook.yml"
        (project / playbook).write_text(files["playbook"])
    (pdd / "inventory").mkdir()
    (pdd / "inventory" / "hosts.yml").write_text(files["inventory"])
    ansible_home = pdd / "ansible"
    ansible_home.mkdir(mode=0o700)
    os.environ["ANSIBLE_HOME"] = str(ansible_home)
    os.environ["ANSIBLE_SSH_CONTROL_PATH_DIR"] = str(ansible_home / "cp")
    if own_home:
        os.environ["HOME"] = _own_home()
        (pdd / "tmp").mkdir(mode=0o700)
        os.environ["TMPDIR"] = str(pdd / "tmp")
    job["private_data_dir"] = str(pdd)
    job["playbook"] = playbook
    job["inventory"] = str(pdd / "inventory" / "hosts.yml")
    return str(pdd)


def _own_home() -> str:
    """The slot user's home, made private again: an earlier run as this user could have
    opened it up for another slot to plant files in (ansible's local tasks run modules from
    it). The sweep emptied it of this user's files, so anything left belongs to someone else
    and the run must not start."""
    home = pwd.getpwuid(os.getuid()).pw_dir
    os.chmod(home, 0o700)
    if leftovers := os.listdir(home):
        raise RuntimeError(f"{home} holds files of another user: {sorted(leftovers)[:5]}")
    return home


# A refresh fails if any source fails to parse (by default ansible only warns, and a run would
# quietly see fewer hosts), reads plugin configs and YAML only, and never asks a cloud
# metadata service for the worker host's own identity.
INVENTORY_ENV = {
    "ANSIBLE_INVENTORY_ENABLED": "auto,yaml",
    "ANSIBLE_INVENTORY_ANY_UNPARSED_IS_FAILED": "True",
    "ANSIBLE_INVENTORY_UNPARSED_FAILED": "True",
    "AWS_EC2_METADATA_DISABLED": "true",
}
_OUTPUT_CHUNK = 512 * 1024
_STDERR_TAIL = 16 * 1024


def run_inventory(job: dict, emit) -> None:
    """An inventory refresh: ansible-inventory --list --export over the job's files (sources,
    the inventory's own hosts, constructed sources), its output sent back in "output"
    messages, then {"type": "inventory_result", "rc", "stderr" (the end of it)} and the usual
    "result". The plugins run in a grandchild that can't reach the message pipe."""
    import subprocess

    base = "/tmp" if os.path.isdir("/tmp") else None  # noqa: S108 - short socket paths; mkdtemp is private
    pdd = Path(tempfile.mkdtemp(prefix=job.get("prefix", "ansideck-refresh-"), dir=base))
    emit({"type": "started", "private_data_dir": str(pdd)})
    try:
        if job.get("own_home"):
            os.environ["HOME"] = _own_home()
        inventory = pdd / "inventory"
        inventory.mkdir(mode=0o700)
        paths = []
        for item in job["files"]:
            name = item["name"]
            if "/" in name or name.startswith("."):
                raise RuntimeError(f"invalid file name {name!r}")
            path = inventory / name
            path.write_text(item["text"])
            path.chmod(0o600)
            paths.append(str(path))
        (pdd / "tmp").mkdir(mode=0o700)
        env = {
            **os.environ,
            "ANSIBLE_HOME": str(pdd / "ansible"),
            "TMPDIR": str(pdd / "tmp"),
            **job.get("env", {}),
            **INVENTORY_ENV,
        }
        output, stderr = pdd / "out.json", pdd / "stderr.txt"
        command = [str(Path(sys.executable).parent / "ansible-inventory")]
        for path in paths:
            command += ["-i", path]
        command += ["--list", "--export", "--output", str(output)]
        with open(stderr, "wb") as err:
            rc = subprocess.run(  # noqa: S603 - argument list, no shell
                command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=err,
                env=env, cwd=pdd, check=False,
            ).returncode  # fmt: skip
        with open(stderr, "rb") as err:
            err.seek(max(0, err.seek(0, os.SEEK_END) - _STDERR_TAIL))
            tail = err.read().decode("utf-8", "replace")
        size = output.stat().st_size if rc == 0 and output.exists() else 0
        if size > job.get("max_output_bytes", 32 * 1024 * 1024):
            rc, tail = 1, f"the output is larger than {job['max_output_bytes']} bytes"
        elif rc == 0:
            with open(output, encoding="utf-8") as out:
                while chunk := out.read(_OUTPUT_CHUNK):
                    emit({"type": "output", "data": chunk})
        emit({"type": "inventory_result", "rc": rc, "stderr": tail})
        emit({"type": "result", "status": "successful" if rc == 0 else "failed", "rc": rc})
    finally:
        shutil.rmtree(pdd, ignore_errors=True)


# ansible-lint config keys a repository may not set: write_list makes ansible-lint rewrite files
# (even without --fix) and hide what it "fixed"; the others write elsewhere or change where and
# how it looks. Its CLI options win for some of them, but not for all.
_LINT_CONFIG_DROPPED = (
    "write_list", "offline", "project_dir", "sarif_file", "cache_dir", "extra_vars",
)  # fmt: skip
_LINT_CONFIG_NAMES = (
    ".ansible-lint",
    ".ansible-lint.yml",
    ".ansible-lint.yaml",
    ".config/ansible-lint.yml",
    ".config/ansible-lint.yaml",
)
# Findings that mean the file couldn't be checked at all, whatever severity ansible-lint gives.
_LINT_ERROR_RULES = ("load-failure", "syntax-check", "internal-error", "parser-error")
_LINT_MAX_OUTPUT = 16 * 1024 * 1024
_LINT_EXIT_MEANING = {3: "ansible-lint's configuration is invalid"}
# Colour codes ansible-lint writes to stderr even with --nocolor (configuration errors).
_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def lint_config(project: Path) -> str:
    """The -c argument for ansible-lint. Always given: without it ansible-lint looks for a
    config in parent directories too, up to the shared /tmp, where another slot could plant
    one. A repository's own config (from its root only) is used without the keys in
    _LINT_CONFIG_DROPPED and without custom rule directories outside the repository; it is
    rewritten in place (relative paths keep their meaning), as a new file, never through a
    link."""
    import yaml

    inside = os.path.realpath(project) + os.sep
    for name in _LINT_CONFIG_NAMES:
        path = project / name
        if path.is_file() and os.path.realpath(path).startswith(inside):
            break
    else:
        return "/dev/null"  # ansible-lint's own spelling of "no configuration file"
    try:
        config = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, UnicodeDecodeError, OSError) as exc:
        raise RuntimeError(f"the repository's {name} can't be read") from exc
    if config is None:
        config = {}
    if not isinstance(config, dict):
        raise RuntimeError(f"the repository's {name} is not a mapping")
    for key in _LINT_CONFIG_DROPPED:
        config.pop(key, None)
    if "rulesdir" in config:
        entries = config["rulesdir"] if isinstance(config["rulesdir"], list) else []
        config["rulesdir"] = [
            entry
            for entry in entries
            if isinstance(entry, str)
            and entry
            and not entry.startswith(("/", "~"))
            and "$" not in entry
            and os.path.realpath(project / entry).startswith(inside)
        ]
    path.unlink()
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    return str(path)


def _int_or_none(value) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def lint_findings(issues, target: str, max_findings: int, clean) -> tuple[list[dict], int, int]:
    """ansible-lint's codeclimate issues as compact findings: (the first max_findings, target
    file first; how many there were; how many were in files outside the project, such as an
    installed collection, and left out)."""
    findings: list[dict] = []
    external = 0
    for issue in issues if isinstance(issues, list) else []:
        if not isinstance(issue, dict):
            continue
        location = issue.get("location") if isinstance(issue.get("location"), dict) else {}
        path = clean(str(location.get("path") or target))
        if path.startswith(("/", "..")):
            external += 1
            continue
        begin = (location.get("positions") or {}).get("begin") or {}
        line = _int_or_none(begin.get("line")) or _int_or_none(
            (location.get("lines") or {}).get("begin")
        )
        rule = str(issue.get("check_name") or "unknown")[:100]
        severe = issue.get("severity") in ("major", "critical", "blocker") or (
            rule.split("[")[0] in _LINT_ERROR_RULES
        )
        content = issue.get("content") if isinstance(issue.get("content"), dict) else {}
        body = content.get("body")
        url = issue.get("url")
        findings.append(
            {
                "rule": rule,
                "level": "error" if severe else "warning",
                "message": clean(str(issue.get("description") or rule))[:500],
                "details": clean(str(body))[:2000] if body else None,
                "path": path[:1024],
                "line": max(1, line or 1),
                "column": _int_or_none(begin.get("column")),
                "url": url[:300] if isinstance(url, str) and url.startswith("https://") else None,
            }
        )
    findings.sort(key=lambda f: (f["path"] != target, f["path"], f["line"], f["column"] or 0))
    return findings[:max_findings], len(findings), external


def run_lint(job: dict, emit) -> None:
    """A playbook check: ansible-lint over the job's content (written as playbook.yml) or, for
    a playbook synced from git, over its repository (a tar after the job line on stdin, as for
    runs) with the repository's own config, roles and collections. Offline, nothing written
    back. Sends {"type": "lint_result", "rc", "findings", "total", "truncated", "external",
    "error", "version"} and the usual "result". ansible-lint runs in a grandchild that can't
    reach the message pipe; it loads collection and module code like a run does."""
    import subprocess
    from importlib.metadata import version

    base = "/tmp" if os.path.isdir("/tmp") else None  # noqa: S108 - short paths; mkdtemp is private
    pdd = Path(tempfile.mkdtemp(prefix=job.get("prefix", "ansideck-lint-"), dir=base))
    emit({"type": "started", "private_data_dir": str(pdd)})
    try:
        if job.get("own_home"):
            os.environ["HOME"] = _own_home()
        for name in ("tmp", "ansible", "cache", "config"):
            (pdd / name).mkdir(mode=0o700)
        project = pdd / "project"
        project.mkdir(mode=0o700)
        env = dict(os.environ)
        if job.get("project") is not None:
            unpack_project(sys.stdin.buffer, project)
            target = project_playbook(project, job["project"]["playbook"])
            env["ANSIBLE_ROLES_PATH"] = _search_path(
                project, "ANSIBLE_ROLES_PATH", ("roles_path",), "roles"
            )
            env["ANSIBLE_COLLECTIONS_PATH"] = _search_path(
                project,
                "ANSIBLE_COLLECTIONS_PATH",
                ("collections_path", "collections_paths"),
                "collections",
            )
            config = lint_config(project)
        else:
            target = "playbook.yml"
            (project / target).write_text(job["content"], encoding="utf-8")
            (project / target).chmod(0o600)
            config = "/dev/null"
        bin_dir = str(Path(sys.executable).parent)
        for name in ("ANSIBLE_LINT_CUSTOM_RULESDIR", "ANSIBLE_LINT_NODEPS", "VIRTUAL_ENV"):
            env.pop(name, None)
        env.update(
            {
                "ANSIBLE_HOME": str(pdd / "ansible"),
                "TMPDIR": str(pdd / "tmp"),
                "ANSIBLE_LOCAL_TEMP": str(pdd / "tmp"),
                "XDG_CACHE_HOME": str(pdd / "cache"),
                "XDG_CONFIG_HOME": str(pdd / "config"),
                "ANSIBLE_LINT_SKIP_SCHEMA_UPDATE": "1",
                "NO_COLOR": "1",
                "ANSIBLE_NOCOLOR": "1",
                # ansible-lint runs ansible-playbook --syntax-check from PATH
                "PATH": os.pathsep.join([bin_dir, env.get("PATH", "")]),
            }
        )
        output, stderr = pdd / "out.json", pdd / "stderr.txt"
        command = [
            str(Path(bin_dir) / "ansible-lint"),
            "--offline", "--nocolor", "-f", "codeclimate",
            "--project-dir", str(project), "-c", config, target,
        ]  # fmt: skip
        with open(output, "wb") as out, open(stderr, "wb") as err:
            rc = subprocess.run(  # noqa: S603 - argument list, no shell
                command, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                env=env, cwd=project, check=False,
            ).returncode  # fmt: skip

        prefixes = sorted(
            {str(project), os.path.realpath(project), str(pdd), os.path.realpath(pdd)},
            key=len,
            reverse=True,
        )

        def clean(text: str) -> str:
            for prefix in prefixes:
                text = text.replace(prefix + os.sep, "").replace(prefix, ".")
            return text

        with open(stderr, "rb") as err:
            err.seek(max(0, err.seek(0, os.SEEK_END) - _STDERR_TAIL))
            tail = _ANSI.sub("", clean(err.read().decode("utf-8", "replace"))).strip()
        findings: list[dict] = []
        total = external = 0
        error = None
        if rc in (0, 2):
            try:
                if output.stat().st_size > _LINT_MAX_OUTPUT:
                    raise ValueError("too large")
                lines = output.read_text(encoding="utf-8").splitlines()
                issues = json.loads(next(line for line in reversed(lines) if line.startswith("[")))
            except (ValueError, StopIteration, OSError):
                error = "ansible-lint's output couldn't be read"
            else:
                findings, total, external = lint_findings(
                    issues, target, job.get("max_findings", 500), clean
                )
        else:
            meaning = _LINT_EXIT_MEANING.get(rc, f"ansible-lint failed (exit {rc})")
            last = "\n".join(tail.splitlines()[-15:])
            error = f"{meaning}: {last}" if last else meaning
        emit(
            {
                "type": "lint_result",
                "rc": rc,
                "findings": findings,
                "total": total,
                "truncated": total > len(findings),
                "external": external,
                "error": error[:1000] if error else None,
                "version": version("ansible-lint"),
            }
        )
        emit({"type": "result", "status": "failed" if error else "successful", "rc": rc})
    finally:
        shutil.rmtree(pdd, ignore_errors=True)


def run(job: dict) -> None:
    event_fd = job.pop("event_fd")
    # Not inherited by anything the playbook spawns, so it can't forge results.
    os.set_inheritable(event_fd, False)
    events = os.fdopen(event_fd, "w", encoding="utf-8")

    def emit(message: dict) -> None:
        events.write(json.dumps(message) + "\n")
        events.flush()

    if job.get("mode") in ("inventory", "lint"):
        try:
            (run_inventory if job["mode"] == "inventory" else run_lint)(job, emit)
        except Exception as exc:  # noqa: BLE001 - reported, the job fails with this reason
            emit({"type": "refused", "reason": str(exc)[:300]})
        return

    # Must return None: ansible-runner writes its own unscrubbed job_events when the
    # handler returns truthy. Scrubbing happens in the parent, before anything is stored.
    def on_event(event: dict) -> None:
        emit({"type": "event", "event": event})

    import ansible_runner  # here, not at the top: --sweep should start fast

    try:
        pdd = prepare(job)
    except Exception as exc:  # noqa: BLE001 - reported, the run fails with this reason
        emit({"type": "refused", "reason": str(exc)[:300]})
        return
    emit({"type": "started", "private_data_dir": pdd})
    try:
        runner = ansible_runner.run(event_handler=on_event, **job)
        emit({"type": "result", "status": runner.status, "rc": runner.rc})
    finally:
        shutil.rmtree(pdd, ignore_errors=True)


def kill_own_processes(rounds: int = _SWEEP_KILL_ROUNDS) -> None:
    """SIGKILLs every process of this user but this one, until there are none left (kill(-1)
    reaches all of them at once, so nothing can fork away from a tree walk)."""
    for _ in range(rounds):
        try:
            os.kill(-1, signal.SIGKILL)
        except ProcessLookupError:
            return
        time.sleep(0.01)  # dead ones stay signalable until reaped (as zombies)


def remove_own_files(roots: list[str]) -> None:
    """Deletes every file and directory this user owns under `roots`, without following
    symlinks or leaving each root's filesystem. What it can't delete stays (the worker then
    sees the slot is still dirty only through its processes; files can't run)."""
    uid = os.getuid()
    for root in roots:
        try:
            root_dev = os.lstat(root).st_dev
        except OSError:
            continue
        for dirpath, dirnames, filenames in os.walk(root, onerror=lambda _e: None):
            for name in filenames:
                path = os.path.join(dirpath, name)
                with contextlib.suppress(OSError):
                    if os.lstat(path).st_uid == uid:
                        os.unlink(path)
            keep = []
            for name in dirnames:
                path = os.path.join(dirpath, name)
                try:
                    info = os.lstat(path)
                except OSError:
                    continue
                if stat.S_ISLNK(info.st_mode):  # os.walk lists symlinks to dirs here
                    if info.st_uid == uid:
                        with contextlib.suppress(OSError):
                            os.unlink(path)
                    continue
                if info.st_dev != root_dev:
                    continue
                if info.st_uid == uid:
                    shutil.rmtree(path, ignore_errors=True)
                else:
                    keep.append(name)
            dirnames[:] = keep


def clear_home(home: str) -> bool:
    """Makes the home private again and empties it of other users' files (its owner may
    delete any entry of it). False if another user's directory stays: this user may not be
    able to empty it."""
    try:
        os.chmod(home, 0o700)
        names = os.listdir(home)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    clean = True
    for name in names:
        path = os.path.join(home, name)
        try:
            if stat.S_ISDIR(os.lstat(path).st_mode):
                shutil.rmtree(path)
            else:
                os.unlink(path)
        except OSError:
            clean = False
    return clean


def sweep(roots: list[str]) -> int:
    if os.getuid() < _RUN_UID_BASE:
        sys.exit("--sweep only runs as a run user")
    kill_own_processes()
    # Closed first: with every process of this user gone, nothing can reopen it.
    home_clean = clear_home(pwd.getpwuid(os.getuid()).pw_dir)
    remove_own_files(roots)
    return 0 if home_clean else HOME_NOT_CLEAN


def main() -> int:
    if sys.argv[1:2] == ["--sweep"]:
        return sweep(sys.argv[2:])
    run(json.loads(sys.stdin.buffer.readline()))
    return 0


if __name__ == "__main__":
    code = main()
    # Hard exit: on failure paths ansible-runner can leave a non-daemon thread behind,
    # and a normal interpreter shutdown would then wait on it forever. Every message
    # has already been flushed by emit().
    os._exit(code)
