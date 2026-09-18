from pathlib import Path

from app.config import get_settings


def playbooks_dir() -> Path:
    path = Path(get_settings().data_dir) / "playbooks"
    path.mkdir(parents=True, exist_ok=True)
    return path


def playbook_path(playbook_id: int) -> Path:
    return playbooks_dir() / f"{playbook_id}.yml"
