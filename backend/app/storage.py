from pathlib import Path

from app.config import get_settings


def playbooks_dir() -> Path:
    path = Path(get_settings().data_dir) / "playbooks"
    path.mkdir(parents=True, exist_ok=True)
    return path


def playbook_path(playbook_id: int) -> Path:
    return playbooks_dir() / f"{playbook_id}.yml"


def runs_dir() -> Path:
    path = Path(get_settings().data_dir) / "runs"
    path.mkdir(parents=True, exist_ok=True)
    return path


def run_log_path(run_id: int) -> Path:
    return runs_dir() / f"{run_id}.jsonl"


def galaxy_dir() -> Path:
    path = Path(get_settings().data_dir) / "galaxy"
    path.mkdir(parents=True, exist_ok=True)
    return path


def galaxy_collections_dir() -> Path:
    path = galaxy_dir() / "collections"
    path.mkdir(parents=True, exist_ok=True)
    return path


def galaxy_roles_dir() -> Path:
    path = galaxy_dir() / "roles"
    path.mkdir(parents=True, exist_ok=True)
    return path


def galaxy_requirements_path() -> Path:
    return galaxy_dir() / "requirements.yml"


def galaxy_install_log_path(install_id: int) -> Path:
    path = galaxy_dir() / "installs"
    path.mkdir(parents=True, exist_ok=True)
    return path / f"{install_id}.log"


def git_dir() -> Path:
    path = Path(get_settings().data_dir) / "git"
    path.mkdir(parents=True, exist_ok=True)
    return path


def git_mirror_path(source_id: int) -> Path:
    """A source's bare fetch mirror (created by app.git_sync)."""
    parent = git_dir() / "mirrors"
    parent.mkdir(parents=True, exist_ok=True)
    return parent / f"{source_id}.git"


def git_snapshot_dir(source_id: int) -> Path:
    """A source's snapshot tars, one per synced commit."""
    path = git_dir() / "snapshots" / str(source_id)
    path.mkdir(parents=True, exist_ok=True)
    return path
