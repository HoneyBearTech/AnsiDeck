"""Runs one ansible-runner job in a child process (app.run_worker) and relays its events.

Imports only the standard library (nothing from app.*), so it can move into the Phase 4B
worker process, which has no database or encryption key; process isolation (a separate
UID or sandbox, Phase 4C) goes here too.
"""

import contextlib
import json
import logging
import os
import signal
import subprocess
import sys
import threading
from collections import defaultdict
from collections.abc import Callable
from pathlib import Path

logger = logging.getLogger(__name__)

_BACKEND_ROOT = Path(__file__).resolve().parents[1]
_WORKER_COMMAND = [sys.executable, "-m", "app.run_worker"]
_WORKER_STOP_GRACE_SECONDS = 10
# ansible-runner checks for a cancel (our SIGTERM) once per pexpect wait, 5 s by default.
_CANCEL_POLL_SECONDS = 1


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
        ["ps", "-axwwo", "pid=,ppid=,command="], capture_output=True, text=True, check=False
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


def run_in_worker(
    job: dict,
    env: dict[str, str],
    on_event: Callable[[dict], None],
    handle: ExecutionHandle | None = None,
) -> tuple[str | None, int | None]:
    """Runs ansible-runner in a child process started with `env` instead of the app's
    environment (see app.run_worker). Returns (ansible-runner status, rc); status is
    None if the worker died without reporting a result."""
    read_fd, write_fd = os.pipe()
    try:
        proc = subprocess.Popen(
            _WORKER_COMMAND,
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
    try:
        with os.fdopen(read_fd, encoding="utf-8") as events:
            assert proc.stdin is not None
            # The job (SSH key, vault password) travels over stdin — never argv or env.
            settings = {"pexpect_timeout": _CANCEL_POLL_SECONDS}
            proc.stdin.write(
                json.dumps({"settings": settings, **job, "event_fd": write_fd}).encode()
            )
            proc.stdin.close()
            for line in events:
                message = json.loads(line)
                if message["type"] == "event":
                    on_event(message["event"])
                elif message["type"] == "result":
                    result = (message["status"], message["rc"])
    except BaseException:
        stop_worker(proc)
        kill_leftovers(job["private_data_dir"])
        raise
    try:
        returncode = proc.wait(timeout=_WORKER_STOP_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        stop_worker(proc)
        returncode = proc.returncode
    # Nothing of the run may outlive it: after a cancel, ansible's task workers would.
    kill_leftovers(job["private_data_dir"])
    if result[0] is None:
        logger.error("run worker exited (code %s) without reporting a result", returncode)
        return None, returncode or None
    return result
