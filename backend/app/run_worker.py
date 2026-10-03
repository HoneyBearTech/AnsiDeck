"""Child-process entry point that actually runs ansible-runner (python -m app.run_worker).

ansible-runner seeds the playbook's environment from os.environ with no way to opt out,
so run_executor spawns this module with an allowlisted environment instead of running
ansible-runner in the app process. Deliberately imports nothing from app.* — in
particular not app.config, which would load the app's secrets.

Protocol: one JSON job on stdin: ansible_runner.run kwargs plus "event_fd", "files"
({"playbook": text, "inventory": text}), "prefix" (of the private data dir's name) and
"own_home" (isolated runs: use, and check, the slot user's home; see app.run_isolation).
One JSON line per message on the inherited event_fd: {"type": "started",
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


def prepare(job: dict) -> str:
    """Creates the run's private data dir (0700) with its playbook and inventory, and gives
    ansible a home of its own in it: its SSH ControlPersist sockets (~/.ansible/cp) would
    otherwise be shared, and a run could ride another run's authenticated connection to the
    same user@host. Returns the private data dir."""
    files = job.pop("files")
    own_home = job.pop("own_home", False)
    # Short paths: SSH's control and agent sockets live in here (104-108 byte limit).
    base = "/tmp" if os.path.isdir("/tmp") else None
    pdd = Path(tempfile.mkdtemp(prefix=job.pop("prefix", "ansideck-run-"), dir=base))
    (pdd / "project").mkdir()
    (pdd / "project" / "playbook.yml").write_text(files["playbook"])
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
    job["playbook"] = "playbook.yml"
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


def run(job: dict) -> None:
    event_fd = job.pop("event_fd")
    # Not inherited by anything the playbook spawns, so it can't forge results.
    os.set_inheritable(event_fd, False)
    events = os.fdopen(event_fd, "w", encoding="utf-8")

    def emit(message: dict) -> None:
        events.write(json.dumps(message) + "\n")
        events.flush()

    # Must return None: ansible-runner writes its own unscrubbed job_events when the
    # handler returns truthy. Scrubbing happens in the parent, before anything is stored.
    def on_event(event: dict) -> None:
        emit({"type": "event", "event": event})

    import ansible_runner  # here, not at the top: --sweep should start fast

    pdd = prepare(job)
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
    run(json.load(sys.stdin))
    return 0


if __name__ == "__main__":
    code = main()
    # Hard exit: on failure paths ansible-runner can leave a non-daemon thread behind,
    # and a normal interpreter shutdown would then wait on it forever. Every message
    # has already been flushed by emit().
    os._exit(code)
