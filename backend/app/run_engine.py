import json
import os
import shutil
import socket
import tempfile
import threading
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
from app.notify import notifier, run_topic
from app.run_executor import host_counts, run_in_worker
from app.scrub import build_scrubber, collect_secrets
from app.storage import playbook_path, run_log_path
from app.subprocess_env import clean_env

# Recorded on each run this process executes (4B's workers will each have their own).
WORKER_ID = f"{socket.gethostname()}:{os.getpid()}"


def _assert_same_project(run: Run, obj, label: str) -> None:
    """Defense in depth: the API already rejects cross-project references, but the
    engine is what decrypts secrets, so it re-checks before using them."""
    if obj is None or obj.project_id != run.project_id:
        raise RuntimeError(f"run {run.id}: {label} is not in the run's project")


def _execute_run(run_id: int, private_data_dir: str | None = None) -> None:
    db = get_sessionmaker()()
    topic = run_topic(run_id)
    run = db.get(Run, run_id)
    if run is None:
        db.close()
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
                    notifier.notify(topic)

                status, return_code = run_in_worker(
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
        db.close()
        notifier.notify(topic)  # the status is final: live log viewers can finish


def start_run(run_id: int) -> None:
    threading.Thread(target=_execute_run, args=(run_id,), daemon=True).start()
