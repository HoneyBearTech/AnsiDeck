import importlib.util
import json
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "check_branch_coverage.py"
_spec = importlib.util.spec_from_file_location("check_branch_coverage", SCRIPT)
assert _spec and _spec.loader
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)
check = _module.check


def _report(tmp_path: Path, totals: dict) -> str:
    path = tmp_path / "coverage.json"
    path.write_text(json.dumps({"totals": totals}))
    return str(path)


def test_passes_at_or_above_the_floor(tmp_path: Path, capsys) -> None:
    report = _report(tmp_path, {"num_branches": 100, "covered_branches": 80})
    assert check(report, 80) == 0  # exactly at the floor still passes
    assert "80.0%" in capsys.readouterr().out


def test_fails_below_the_floor(tmp_path: Path, capsys) -> None:
    report = _report(tmp_path, {"num_branches": 100, "covered_branches": 79})
    assert check(report, 80) == 1
    assert "BELOW THE FLOOR" in capsys.readouterr().out


def test_a_report_without_branch_data_is_an_error_not_a_pass(tmp_path: Path, capsys) -> None:
    # e.g. branch coverage was switched off: the gate must not silently succeed.
    assert check(_report(tmp_path, {"covered_lines": 10}), 80) == 2
    assert check(_report(tmp_path, {"num_branches": 0, "covered_branches": 0}), 80) == 2
    assert "No branch data" in capsys.readouterr().out
