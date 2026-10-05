"""The committed API descriptions in docs/api/ match the code."""

import pytest

from scripts.export_openapi import DOCS, SPECS, render


@pytest.mark.parametrize("name", sorted(SPECS))
def test_the_committed_api_description_is_current(name) -> None:
    committed = (DOCS / name).read_text()
    assert committed == render(name), (
        f"docs/api/{name} is out of date: run `uv run python scripts/export_openapi.py`"
    )
