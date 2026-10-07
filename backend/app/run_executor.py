"""Runs one ansible-runner job in a child process (app.run_worker) and relays its events.

Imports only the standard library and app.run_isolation (also standard library only): it
runs in the worker process, which has no database or encryption key. With a RunIdentity the
child runs as that slot's own user, and sweep() cleans up after it (Phase 4C).
"""

import contextlib
import json
import logging
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections import defaultdict
from collections.abc import Callable
from pathlib import Path

from app.run_isolation import SWEEP_DIRS, RunIdentity, replace_home, wrap

logger = logging.getLogger(__name__)

_BACKEND_ROOT = Path(__file__).resolve().parents[1]
_WORKER_COMMAND = [sys.executable, "-m", "app.run_worker"]
_WORKER_STOP_GRACE_SECONDS = 10
# ansible-runner checks for a cancel (our SIGTERM) once per pexpect wait, 5 s by default.
_CANCEL_POLL_SECONDS = 1
_SWEEP_TIMEOUT_SECONDS = 60
_SWEEP_ATTEMPTS = 3
_HOME_NOT_CLEAN = 3  # app.run_worker.HOME_NOT_CLEAN (not imported: that loads ansible)
# app.run_worker.MAX_MESSAGE_BYTES: the run process never sends a longer line, so one is a
# misbehaving process, and reading it whole could exhaust the worker's memory (every slot).
_MAX_MESSAGE_BYTES = 32 * 1024 * 1024


def format_duration(seconds: int) -> str:
    """ "45 s", "3 min", "2 h", "1 h 30 min": for status reasons."""
    if seconds < 120:
        return f"{seconds} s"
    hours, minutes = divmod(seconds // 60, 60)
    if not hours:
        return f"{minutes} min"
    return f"{hours} h {minutes} min" if minutes else f"{hours} h"


def host_counts(event_data: object) -> dict[str, int]:
    """Hosts per outcome from a playbook_on_stats event's data (ansible's PLAY RECAP:
    per-outcome {host: task count} maps; "dark" is unreachable). Malformed input counts
    as nothing rather than failing the run."""
    data = event_data if isinstance(event_data, dict) else {}

    def hosts(key: str) -> set[str]:
        per_host = data.get(key)
        if not isinstance(per_host, dict):
            return set()
        return {h for h, n in per_host.items() if isinstance(n, int) and n > 0}

    everyone = set().union(
        *(hosts(k) for k in ("processed", "ok", "changed", "failures", "dark", "skipped"))
    )
    failed, unreachable = hosts("failures"), hosts("dark")
    return {
        "hosts_total": len(everyone),
        "hosts_ok": len(everyone - failed - unreachable),
        "hosts_changed": len(hosts("changed")),
        "hosts_failed": len(failed),
        "hosts_unreachable": len(unreachable),
    }


def stop_worker(proc: subprocess.Popen) -> None:
    """SIGTERM makes ansible-runner cancel cleanly; SIGKILL only if that doesn't land."""
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=_WORKER_STOP_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)
        proc.wait()


class ExecutionHandle:
    """Lets another thread stop a job (cancel, timeout, lost lease, shutdown). The first
    reason wins. Stopping is stop_worker() in the background, whether the process has started
    yet or not."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._proc: subprocess.Popen | None = None
        self.stop_reason: str | None = None

    @property
    def pid(self) -> int | None:
        return self._proc.pid if self._proc else None

    def attach(self, proc: subprocess.Popen) -> None:
        with self._lock:
            self._proc = proc
            stopping = self.stop_reason is not None
        if stopping:
            self._stop_in_background(proc)

    def stop(self, reason: str) -> bool:
        with self._lock:
            if self.stop_reason is not None:
                return False
            self.stop_reason = reason
            proc = self._proc
        if proc is not None:
            self._stop_in_background(proc)
        return True

    @staticmethod
    def _stop_in_background(proc: subprocess.Popen) -> None:
        threading.Thread(target=stop_worker, args=(proc,), daemon=True).start()


def processes_of(uid: int) -> list[int]:
    """Live (not zombie) processes whose real, effective, saved or filesystem uid is `uid`
    (Linux; read from /proc/<pid>/status, which stays readable for non-dumpable processes,
    unlike the owner of /proc/<pid> itself)."""
    found = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            status = (entry / "status").read_text()
        except OSError:
            continue
        fields = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
        if fields.get("State", "").split()[:1] == ["Z"]:
            continue
        if str(uid) in fields.get("Uid", "").split():
            found.append(int(entry.name))
    return found


def sweep(identity: RunIdentity) -> bool:
    """Kills every process of the slot's user and deletes its files in the shared temp dirs
    and its home (as that user: the worker never touches a run's files). True once no process
    of it is left and its home is empty and private; False if that failed every attempt, and
    then the slot must not run anything."""
    command = wrap([sys.executable, "-m", "app.run_worker", "--sweep", *SWEEP_DIRS], identity)
    for attempt in range(_SWEEP_ATTEMPTS):
        home_clean = False
        try:
            done = subprocess.run(  # noqa: S603 - argument list, no shell
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
                cwd=_BACKEND_ROOT,
                timeout=_SWEEP_TIMEOUT_SECONDS,
                check=False,
            )
        except subprocess.TimeoutExpired:
            logger.warning("sweeping %s timed out", identity.name)
        else:
            home_clean = done.returncode == 0
            if done.returncode == _HOME_NOT_CLEAN:
                logger.warning("%s's home held another user's files; replacing it", identity.name)
                try:
                    replace_home(identity)
                    home_clean = True
                except OSError:
                    logger.exception("could not replace the home of %s", identity.name)
        left = processes_of(identity.uid)
        if not left and home_clean:
            return True
        logger.warning(
            "%s is not clean after sweep %s (%s process(es) left)",
            identity.name,
            attempt + 1,
            len(left),
        )
        time.sleep(0.5)
    return False


def _process_table() -> dict[int, tuple[int, str]]:
    """{pid: (parent pid, command line)} of every visible process."""
    table: dict[int, tuple[int, str]] = {}
    proc = Path("/proc")
    if proc.is_dir():  # Linux (the slim images have no `ps`)
        for entry in proc.iterdir():
            if not entry.name.isdigit():
                continue
            try:
                stat = (entry / "stat").read_text()
                cmdline = (entry / "cmdline").read_bytes()
            except OSError:
                continue
            ppid = int(stat.rsplit(")", 1)[1].split()[1])
            table[int(entry.name)] = (ppid, cmdline.replace(b"\0", b" ").decode(errors="replace"))
        return table
    # macOS (development). -ww: never truncate, the marker can be far into a command line.
    out = subprocess.run(
        ["ps", "-axwwo", "pid=,ppid=,command="],  # noqa: S607 - ps from the image's PATH
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    for line in out.splitlines():
        fields = line.split(None, 2)
        if len(fields) >= 2:
            table[int(fields[0])] = (int(fields[1]), fields[2] if len(fields) == 3 else "")
    return table


def kill_leftovers(marker: str) -> int:
    """SIGKILLs every process whose command line mentions `marker` (a run's private data
    dir) and all their descendants; returns how many. Needed because ansible's task workers
    move to sessions of their own, so they outlive a cancel that kills ansible-playbook's
    process group (and then hang). Each round freezes what it finds (SIGSTOP), so nothing
    can fork away while the tree is collected."""
    frozen: set[int] = set()
    for _ in range(20):
        table = _process_table()
        children: dict[int, list[int]] = defaultdict(list)
        for pid, (ppid, _command) in table.items():
            children[ppid].append(pid)
        found = {pid for pid, (_ppid, command) in table.items() if marker in command}
        stack = list(found | frozen)
        while stack:
            for child in children[stack.pop()]:
                if child not in found:
                    found.add(child)
                    stack.append(child)
        found.discard(os.getpid())
        new = found - frozen
        if not new:
            break
        for pid in new:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.kill(pid, signal.SIGSTOP)
        frozen |= new
    for pid in frozen:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.kill(pid, signal.SIGKILL)
    if frozen:
        logger.info("killed %s leftover process(es) of %s", len(frozen), marker)
    return len(frozen)


def _clean_up(identity: RunIdentity | None, private_data_dir: str | None) -> None:
    """Nothing of the run may outlive it: after a cancel, ansible's task workers would."""
    if identity is not None:
        if not sweep(identity):
            logger.error("could not end every process of %s", identity.name)
        return
    if private_data_dir is not None:  # not isolated: same user, so find them by the dir
        kill_leftovers(private_data_dir)
        shutil.rmtree(private_data_dir, ignore_errors=True)


def _checked_dir(path: str, job: dict) -> str | None:
    """The child's private data dir, if it looks like one (it is cleaned up by path)."""
    name = os.path.basename(path)
    if os.path.isabs(path) and name.startswith(job.get("prefix", "ansideck-run-")):
        return path
    logger.error("ignoring an unexpected private data dir %r", path)
    return None


def inventory_in_worker(
    job: dict,
    env: dict[str, str],
    handle: ExecutionHandle | None = None,
    identity: RunIdentity | None = None,
) -> tuple[int | None, str, str]:
    """An inventory refresh in the run process (app.run_worker, mode "inventory"), as
    `identity` when given: (ansible-inventory's exit code or None, its output, the end of its
    stderr). RunRefused if it couldn't be set up."""
    chunks: list[str] = []
    outcome: dict = {}

    def on_message(message: dict) -> None:
        if message["type"] == "output":
            chunks.append(message["data"])
        elif message["type"] == "inventory_result":
            outcome.update(rc=message["rc"], stderr=message.get("stderr") or "")

    run_in_worker(
        {**job, "mode": "inventory"}, env, lambda _event: None, handle, identity,
        on_message=on_message,
    )  # fmt: skip
    return outcome.get("rc"), "".join(chunks), outcome.get("stderr", "")


def lint_in_worker(
    job: dict,
    env: dict[str, str],
    handle: ExecutionHandle | None = None,
    identity: RunIdentity | None = None,
    stdin_tail: bytes | None = None,
) -> dict | None:
    """A playbook check in the run process (app.run_worker, mode "lint"), as `identity` when
    given; `stdin_tail` is the repository of a synced playbook. Returns the "lint_result"
    message, or None if the process died without one. RunRefused if it couldn't be set up."""
    outcome: dict = {}

    def on_message(message: dict) -> None:
        if message["type"] == "lint_result":
            outcome.update(message)

    run_in_worker(
        {**job, "mode": "lint"}, env, lambda _event: None, handle, identity,
        stdin_tail=stdin_tail, on_message=on_message,
    )  # fmt: skip
    return outcome or None


class RunRefused(Exception):
    """The run process refused to start the run (its message is safe to show)."""


def run_in_worker(
    job: dict,
    env: dict[str, str],
    on_event: Callable[[dict], None],
    handle: ExecutionHandle | None = None,
    identity: RunIdentity | None = None,
    stdin_tail: bytes | None = None,
    on_message: Callable[[dict], None] | None = None,
) -> tuple[str | None, int | None]:
    """Runs ansible-runner in a child process started with `env` instead of the app's
    environment (see app.run_worker), as `identity` when given. Returns (ansible-runner
    status, rc); status is None if the worker died without reporting a result."""
    command = _WORKER_COMMAND if identity is None else wrap(_WORKER_COMMAND, identity)
    read_fd, write_fd = os.pipe()
    try:
        proc = subprocess.Popen(  # noqa: S603 - argument list, no shell
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
            cwd=_BACKEND_ROOT,
            pass_fds=(write_fd,),
            start_new_session=True,
        )
    except BaseException:
        os.close(read_fd)
        raise
    finally:
        os.close(write_fd)
    if handle is not None:
        handle.attach(proc)

    result: tuple[str | None, int | None] = (None, None)
    private_data_dir: str | None = None
    refused: str | None = None
    try:
        with os.fdopen(read_fd, "rb") as events:
            if proc.stdin is None:
                raise RuntimeError("the run worker was started without an input pipe")
            # The job (SSH key, vault password) travels over stdin — never argv or env.
            settings = {"pexpect_timeout": _CANCEL_POLL_SECONDS}
            proc.stdin.write(
                json.dumps({"settings": settings, **job, "event_fd": write_fd}).encode() + b"\n"
            )
            if stdin_tail is not None:
                proc.stdin.write(stdin_tail)  # a git run's repository (a tar), after the job
            proc.stdin.close()
            while line := events.readline(_MAX_MESSAGE_BYTES + 1):
                if len(line) > _MAX_MESSAGE_BYTES:
                    raise RuntimeError(
                        f"the run process sent over {_MAX_MESSAGE_BYTES} bytes in one line"
                    )
                message = json.loads(line)
                if message["type"] == "event":
                    on_event(message["event"])
                elif message["type"] == "started":
                    private_data_dir = _checked_dir(message["private_data_dir"], job)
                elif message["type"] == "result":
                    result = (message["status"], message["rc"])
                elif message["type"] == "refused":
                    refused = str(message.get("reason") or "refused")
                elif on_message is not None:  # an inventory refresh's output and result
                    on_message(message)
    except BaseException:
        stop_worker(proc)
        _clean_up(identity, private_data_dir)
        raise
    try:
        returncode = proc.wait(timeout=_WORKER_STOP_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        stop_worker(proc)
        returncode = proc.returncode
    _clean_up(identity, private_data_dir)
    if refused is not None:
        raise RunRefused(refused)
    if result[0] is None:
        logger.error("run worker exited (code %s) without reporting a result", returncode)
        return None, returncode or None
    return result
