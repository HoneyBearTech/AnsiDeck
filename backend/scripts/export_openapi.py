"""Writes the OpenAPI descriptions of the public and internal APIs to docs/api/.

    uv run python scripts/export_openapi.py

A test fails when the committed files differ from what the code describes, so run this after
changing a route or a schema.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.internal_api import internal_app
from app.main import app

DOCS = Path(__file__).resolve().parents[2] / "docs" / "api"
SPECS = {"openapi.json": app, "internal-openapi.json": internal_app}


def render(name: str) -> str:
    return json.dumps(SPECS[name].openapi(), indent=2, sort_keys=True) + "\n"


def main() -> None:
    DOCS.mkdir(parents=True, exist_ok=True)
    for name in SPECS:
        (DOCS / name).write_text(render(name))
        print(f"wrote docs/api/{name}")


if __name__ == "__main__":
    main()
