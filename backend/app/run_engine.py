import asyncio
import json
import shutil
import tempfile
import threading
from datetime import UTC, datetime
from pathlib import Path

import ansible_runner

from app.crypto import decrypt_secret
from app.db import get_sessionmaker
from app.inventory_render import render_inventory_yaml
from app.models import Credential, Inventory, InventoryGroup, Run, RunStatus, VaultPassword
from app.storage import playbook_path, run_log_path

DONE = object()


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
        run.started_at = datetime.now(UTC)
        db.commit()

        credential = db.get(Credential, run.credential_id)
        private_key_pem = decrypt_secret(credential.encrypted_private_key).decode()

        vault_password_plain = None
        if run.vault_password_id is not None:
            vault_password = db.get(VaultPassword, run.vault_password_id)
            vault_password_plain = decrypt_secret(vault_password.encrypted_password).decode()

        inventory_obj = db.get(Inventory, run.inventory_id)
        group_obj = db.get(InventoryGroup, run.group_id) if run.group_id else None
        rendered_inventory = render_inventory_yaml(inventory_obj, group_obj)
        playbook_text = playbook_path(run.playbook_id).read_text()

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
                    log_file.write(json.dumps(event) + "\n")
                    log_file.flush()
                    stream.publish(event)

                flags = []
                if run.become:
                    flags.append("--become")
                if run.check_mode:
                    flags.append("--check")
                if run.diff_mode:
                    flags.append("--diff")
                if vault_password_plain is not None:
                    flags.append("--ask-vault-pass")

                runner = ansible_runner.run(
                    private_data_dir=pdd,
                    playbook="playbook.yml",
                    inventory=str(inventory_path),
                    ssh_key=private_key_pem,
                    cmdline=" ".join(flags) or None,
                    limit=run.limit,
                    extravars=run.extra_vars or {},
                    passwords=(
                        {r"Vault password:\s*?$": vault_password_plain}
                        if vault_password_plain is not None
                        else None
                    ),
                    event_handler=on_event,
                )
        finally:
            shutil.rmtree(pdd, ignore_errors=True)

        run.status = (
            RunStatus.SUCCESS.value if runner.status == "successful" else RunStatus.FAILED.value
        )
        run.return_code = runner.rc
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
