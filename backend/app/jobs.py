"""Turns a claimed run into the job a worker executes: decrypted secrets, the rendered
inventory, the playbook snapshot, ansible flags and the list of secrets to scrub from output.

Only the API can build it (it alone holds the encryption key); a worker receives it once, over
the internal API, with a one-time token.
"""

import hashlib

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.git_sync import snapshot_path, vars_texts
from app.inventory_render import all_vars_dicts, merge, render, static_data
from app.models import (
    Credential,
    GitSnapshot,
    Inventory,
    InventorySnapshot,
    Run,
    VaultPassword,
)
from app.scrub import collect_secrets
from app.secret_store import (
    SecretStoreError,
    new_deadline,
    resolve_credential,
    resolve_vault_password,
)


def unrunnable_reason(run: Run) -> str | None:
    """Why a queued run can no longer run as it was triggered (something it needs was deleted
    since), or None. Running it anyway would do something else: without its group, for one,
    it would target the whole inventory."""
    if run.playbook_snapshot is None:
        return "its playbook snapshot is missing"
    if run.playbook_id is None:
        return "its playbook was deleted"
    if run.inventory_id is None:
        return "its inventory was deleted"
    if run.credential_id is None:
        return "its credential was deleted"
    if run.group_name is not None and run.group_id is None and run.inventory_static is None:
        return f"its inventory group '{run.group_name}' was deleted"
    if run.vault_password_name is not None and run.vault_password_id is None:
        return "its vault password was deleted"
    if run.git_commit is not None and run.git_snapshot_id is None:
        return "its git source (and the commit it was to run) was deleted"
    return None


# The same conditions as a filter, for finding such runs in the queue.
UNRUNNABLE = or_(
    Run.playbook_snapshot.is_(None),
    Run.playbook_id.is_(None),
    Run.inventory_id.is_(None),
    Run.credential_id.is_(None),
    # A pinned run (4G) carries its target group in the pin: it may be a source's group.
    Run.group_name.is_not(None) & Run.group_id.is_(None) & Run.inventory_static.is_(None),
    Run.vault_password_name.is_not(None) & Run.vault_password_id.is_(None),
    Run.git_commit.is_not(None) & Run.git_snapshot_id.is_(None),
)


def assert_same_project(run: Run, obj, label: str) -> None:
    """Defense in depth: the API already rejects cross-project references, but this is where
    secrets are decrypted, so it re-checks before using them."""
    if obj is None or obj.project_id != run.project_id:
        raise RuntimeError(f"run {run.id}: {label} is not in the run's project")


def extravars(run: Run) -> dict:
    """The run's extra vars as Ansible gets them. A run by someone without runs:become also gets
    ansible_become: false: extra vars outrank every play, task and inventory `become`, so nothing
    in the playbook, the inventory or a source can turn become on either."""
    if run.become_blocked:
        return {**(run.extra_vars or {}), "ansible_become": False}
    return run.extra_vars or {}


def build_job(db: Session, run: Run) -> dict:
    """SecretStoreError (with `.subject` naming the secret) when a credential or vault password
    in the secret store can't be read; one deadline covers all of the job's reads."""
    deadline = new_deadline()
    credential = db.get(Credential, run.credential_id)
    assert_same_project(run, credential, "credential")
    if credential.kind != "ssh":
        raise RuntimeError(f"run {run.id}: its credential is not an SSH key")
    try:
        private_key_pem = resolve_credential(credential, deadline)
    except SecretStoreError as exc:
        exc.subject = f"credential '{credential.name}'"
        raise

    vault_password_plain = None
    if run.vault_password_id is not None:
        vault_password = db.get(VaultPassword, run.vault_password_id)
        assert_same_project(run, vault_password, "vault password")
        try:
            vault_password_plain = resolve_vault_password(vault_password, deadline)
        except SecretStoreError as exc:
            exc.subject = f"vault password '{vault_password.name}'"
            raise

    inventory = db.get(Inventory, run.inventory_id)
    assert_same_project(run, inventory, "inventory")
    # Pinned when triggered; runs queued before 4G see the inventory as it is now.
    static = run.inventory_static if run.inventory_static is not None else static_data(inventory)
    snapshot = None
    if run.inventory_snapshot_id is not None:
        snapshot = db.get(InventorySnapshot, run.inventory_snapshot_id)
        if snapshot is None or snapshot.inventory_id != inventory.id:
            raise RuntimeError(f"run {run.id}: its inventory snapshot is gone or elsewhere")
    graph = merge(static, snapshot.data if snapshot is not None else None)
    if run.group_name is not None and run.group_name not in graph["groups"]:
        raise RuntimeError(f"run {run.id}: group {run.group_name!r} is not in its inventory")
    inventory_text = render(graph, run.group_name)
    run.inventory_sha256 = hashlib.sha256(inventory_text.encode()).hexdigest()

    # A synced playbook runs inside its repository: the worker fetches the snapshot (a tar
    # of the commit) and checks it against this size and hash.
    project = None
    repo_vars: list[str] = []
    if run.git_snapshot_id is not None:
        snapshot = db.get(GitSnapshot, run.git_snapshot_id)
        tar = snapshot_path(snapshot)
        if tar.stat().st_size != snapshot.size_bytes:
            raise RuntimeError(f"run {run.id}: the git snapshot on disk changed")
        project = {
            "playbook": run.playbook_path,
            "bytes": snapshot.size_bytes,
            "sha256": snapshot.sha256,
        }
        repo_vars = vars_texts(snapshot)

    secrets = collect_secrets(
        ssh_key_pem=private_key_pem,
        vault_password=vault_password_plain,
        playbook_text=run.playbook_snapshot,
        extra_vars=run.extra_vars,
        host_vars=all_vars_dicts(graph),
        repo_vars_texts=repo_vars,
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

    return {
        "playbook": run.playbook_snapshot,
        "inventory": inventory_text,
        "ssh_key": private_key_pem,
        "vault_password": vault_password_plain,
        "cmdline": " ".join(flags) or None,
        "limit": run.limit,
        "extravars": extravars(run),
        "timeout_seconds": run.timeout_seconds,
        "secrets": sorted(secrets),
        "project": project,
    }
