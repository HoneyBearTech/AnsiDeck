import asyncio
import contextlib
import json
import logging
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from app.crypto import decrypt_secret
from app.db import get_sessionmaker
from app.galaxy import galaxy_env
from app.inventory_render import render_inventory_yaml
from app.models import (
    Credential,
    Inventory,
    InventoryGroup,
    Playbook,
    Run,
    RunStatus,
    VaultPassword,
)
from app.scrub import build_scrubber, collect_secrets
from app.storage import playbook_path, run_log_path
from app.subprocess_env import clean_env

logger = logging.getLogger(__name__)

DONE = object()

_BACKEND_ROOT = Path(__file__).resolve().parents[1]
_WORKER_COMMAND = [sys.executable, "-m", "app.run_worker"]
_WORKER_STOP_GRACE_SECONDS = 10

# Recorded on each run this process executes (4B's workers will each have their own).
WORKER_ID = f"{socket.gethostname()}:{os.getpid()}"


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


class RunStream:
    def __init__(self) -> None:
        self.events: list[dict] = []
        self.subscribers: list[asyncio.Queue] = []
        self.done = False
        self._lock = threading.Lock()

    def publish(self, event: dict) -> None:
        with self._lock:
            self.events.append(event)
            subscribers = list(self.subscribers)
        if not subscribers:
            return
        loop = get_event_loop()
        for queue in subscribers:
            loop.call_soon_threadsafe(queue.put_nowait, event)

    def mark_done(self) -> None:
        with self._lock:
            self.done = True
            subscribers = list(self.subscribers)
        if not subscribers:
            return
        loop = get_event_loop()
        for queue in subscribers:
            loop.call_soon_threadsafe(queue.put_nowait, DONE)

    def subscribe(self) -> tuple[list[dict], asyncio.Queue]:
        queue: asyncio.Queue = asyncio.Queue()
        with self._lock:
            backlog = list(self.events)
            if self.done:
                queue.put_nowait(DONE)
            else:
                self.subscribers.append(queue)
        return backlog, queue


_streams: dict[int, RunStream] = {}
_streams_lock = threading.Lock()
_event_loop: asyncio.AbstractEventLoop | None = None


def set_event_loop(loop: asyncio.AbstractEventLoop) -> None:
    global _event_loop
    _event_loop = loop


def get_event_loop() -> asyncio.AbstractEventLoop:
    if _event_loop is None:
        raise RuntimeError("run_engine event loop not set — call set_event_loop() at startup")
    return _event_loop


def get_or_create_stream(run_id: int) -> RunStream:
    with _streams_lock:
        stream = _streams.get(run_id)
        if stream is None:
            stream = RunStream()
            _streams[run_id] = stream
        return stream


def _assert_same_project(run: Run, obj, label: str) -> None:
    """Defense in depth: the API already rejects cross-project references, but the
    engine is what decrypts secrets, so it re-checks before using them."""
    if obj is None or obj.project_id != run.project_id:
        raise RuntimeError(f"run {run.id}: {label} is not in the run's project")


def _stop_worker(proc: subprocess.Popen) -> None:
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


def _run_in_worker(
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
        _stop_worker(proc)
        raise
    try:
        returncode = proc.wait(timeout=_WORKER_STOP_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        _stop_worker(proc)
        returncode = proc.returncode
    if result[0] is None:
        logger.error("run worker exited (code %s) without reporting a result", returncode)
        return None, returncode or None
    return result


def _execute_run(run_id: int, private_data_dir: str | None = None) -> None:
    db = get_sessionmaker()()
    stream = get_or_create_stream(run_id)
    run = db.get(Run, run_id)
    if run is None:
        db.close()
        stream.mark_done()
        return

    try:
        run.status = RunStatus.RUNNING.value
        run.claimed_at = datetime.now(UTC)
        run.worker_id = WORKER_ID
        db.commit()

        _assert_same_project(run, db.get(Playbook, run.playbook_id), "playbook")
        credential = db.get(Credential, run.credential_id)
        _assert_same_project(run, credential, "credential")
        private_key_pem = decrypt_secret(credential.encrypted_private_key).decode()

        vault_password_plain = None
        if run.vault_password_id is not None:
            vault_password = db.get(VaultPassword, run.vault_password_id)
            _assert_same_project(run, vault_password, "vault password")
            vault_password_plain = decrypt_secret(vault_password.encrypted_password).decode()

        inventory_obj = db.get(Inventory, run.inventory_id)
        _assert_same_project(run, inventory_obj, "inventory")
        group_obj = db.get(InventoryGroup, run.group_id) if run.group_id else None
        rendered_inventory = render_inventory_yaml(inventory_obj, group_obj)
        playbook_text = playbook_path(run.playbook_id).read_text()

        scrub_event = build_scrubber(
            collect_secrets(
                ssh_key_pem=private_key_pem,
                vault_password=vault_password_plain,
                playbook_text=playbook_text,
                extra_vars=run.extra_vars,
                host_vars=[host.vars or {} for host in inventory_obj.hosts],
            )
        )

        flags = []
        if run.become:
            flags.append("--become")
        if run.check_mode:
            flags.append("--check")
        if run.diff_mode:
            flags.append("--diff")
        if vault_password_plain is not None:
            flags.append("--ask-vault-pass")
        limit, extravars = run.limit, run.extra_vars or {}
        run.started_at = datetime.now(UTC)  # everything is loaded; ansible launches next
        # End the read transaction before the playbook runs: an "idle in transaction"
        # connection for the whole run would pin its locks (blocking migrations/DDL).
        db.commit()

        recap: dict[str, int] = {}
        pdd = private_data_dir or tempfile.mkdtemp(prefix=f"ansideck-run-{run_id}-")
        try:
            project_dir = Path(pdd) / "project"
            project_dir.mkdir(parents=True, exist_ok=True)
            (project_dir / "playbook.yml").write_text(playbook_text)

            inventory_dir = Path(pdd) / "inventory"
            inventory_dir.mkdir(parents=True, exist_ok=True)
            inventory_path = inventory_dir / "hosts.yml"
            inventory_path.write_text(rendered_inventory)

            with run_log_path(run_id).open("w", encoding="utf-8") as log_file:

                def on_event(event: dict) -> None:
                    if event.get("event") == "playbook_on_stats":
                        recap.update(host_counts(event.get("event_data")))
                    event = scrub_event(event)
                    log_file.write(json.dumps(event) + "\n")
                    log_file.flush()
                    stream.publish(event)

                status, return_code = _run_in_worker(
                    {
                        "private_data_dir": pdd,
                        "playbook": "playbook.yml",
                        "inventory": str(inventory_path),
                        "ssh_key": private_key_pem,
                        "cmdline": " ".join(flags) or None,
                        "limit": limit,
                        "extravars": extravars,
                        "passwords": (
                            {r"Vault password:\s*?$": vault_password_plain}
                            if vault_password_plain is not None
                            else None
                        ),
                    },
                    clean_env(galaxy_env()),
                    on_event,
                )
        finally:
            shutil.rmtree(pdd, ignore_errors=True)

        run.status = RunStatus.SUCCESS.value if status == "successful" else RunStatus.FAILED.value
        run.return_code = return_code
        for column, count in recap.items():
            setattr(run, column, count)
    except Exception:
        run.status = RunStatus.FAILED.value
        raise
    finally:
        run.finished_at = datetime.now(UTC)
        db.commit()
        stream.mark_done()
        db.close()


def start_run(run_id: int) -> None:
    threading.Thread(target=_execute_run, args=(run_id,), daemon=True).start()
