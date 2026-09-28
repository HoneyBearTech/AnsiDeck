"""Turns a claimed run into the job a worker executes: decrypted secrets, the rendered
inventory, the playbook snapshot, ansible flags and the list of secrets to scrub from output.

Only the API can build it (it alone holds the encryption key); a worker receives it once, over
the internal API, with a one-time token.
"""

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.crypto import decrypt_secret
from app.inventory_render import render_inventory_yaml
from app.models import Credential, Inventory, InventoryGroup, Run, VaultPassword
from app.scrub import collect_secrets


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
    if run.group_name is not None and run.group_id is None:
        return f"its inventory group '{run.group_name}' was deleted"
    if run.vault_password_name is not None and run.vault_password_id is None:
        return "its vault password was deleted"
    return None


# The same conditions as a filter, for finding such runs in the queue.
UNRUNNABLE = or_(
    Run.playbook_snapshot.is_(None),
    Run.playbook_id.is_(None),
    Run.inventory_id.is_(None),
    Run.credential_id.is_(None),
    Run.group_name.is_not(None) & Run.group_id.is_(None),
    Run.vault_password_name.is_not(None) & Run.vault_password_id.is_(None),
)


def assert_same_project(run: Run, obj, label: str) -> None:
    """Defense in depth: the API already rejects cross-project references, but this is where
    secrets are decrypted, so it re-checks before using them."""
    if obj is None or obj.project_id != run.project_id:
        raise RuntimeError(f"run {run.id}: {label} is not in the run's project")


def build_job(db: Session, run: Run) -> dict:
    credential = db.get(Credential, run.credential_id)
    assert_same_project(run, credential, "credential")
    private_key_pem = decrypt_secret(credential.encrypted_private_key).decode()

    vault_password_plain = None
    if run.vault_password_id is not None:
        vault_password = db.get(VaultPassword, run.vault_password_id)
        assert_same_project(run, vault_password, "vault password")
        vault_password_plain = decrypt_secret(vault_password.encrypted_password).decode()

    inventory = db.get(Inventory, run.inventory_id)
    assert_same_project(run, inventory, "inventory")
    group = db.get(InventoryGroup, run.group_id) if run.group_id else None
    if group is not None and group.inventory_id != inventory.id:
        raise RuntimeError(f"run {run.id}: group is not in the run's inventory")

    secrets = collect_secrets(
        ssh_key_pem=private_key_pem,
        vault_password=vault_password_plain,
        playbook_text=run.playbook_snapshot,
        extra_vars=run.extra_vars,
        host_vars=[host.vars or {} for host in inventory.hosts],
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
        "inventory": render_inventory_yaml(inventory, group),
        "ssh_key": private_key_pem,
        "vault_password": vault_password_plain,
        "cmdline": " ".join(flags) or None,
        "limit": run.limit,
        "extravars": run.extra_vars or {},
        "timeout_seconds": run.timeout_seconds,
        "secrets": sorted(secrets),
    }
