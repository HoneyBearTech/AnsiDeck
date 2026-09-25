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
from collections.abc import Callable
from pathlib import Path

logger = logging.getLogger(__name__)

_BACKEND_ROOT = Path(__file__).resolve().parents[1]
_WORKER_COMMAND = [sys.executable, "-m", "app.run_worker"]
_WORKER_STOP_GRACE_SECONDS = 10


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


def run_in_worker(
    job: dict, env: dict[str, str], on_event: Callable[[dict], None]
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

    result: tuple[str | None, int | None] = (None, None)
    try:
        with os.fdopen(read_fd, encoding="utf-8") as events:
            assert proc.stdin is not None
            # The job (SSH key, vault password) travels over stdin — never argv or env.
            proc.stdin.write(json.dumps({**job, "event_fd": write_fd}).encode())
            proc.stdin.close()
            for line in events:
                message = json.loads(line)
                if message["type"] == "event":
                    on_event(message["event"])
                elif message["type"] == "result":
                    result = (message["status"], message["rc"])
    except BaseException:
        stop_worker(proc)
        raise
    try:
        returncode = proc.wait(timeout=_WORKER_STOP_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        stop_worker(proc)
        returncode = proc.returncode
    if result[0] is None:
        logger.error("run worker exited (code %s) without reporting a result", returncode)
        return None, returncode or None
    return result
