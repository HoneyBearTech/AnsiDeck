"""Fail unless branch coverage in a coverage.py JSON report meets a floor.

coverage.py's own `fail_under` gates the blended line + branch figure, and there are far
more lines than branches, so a falling branch rate can hide behind it. This checks the
branches directly.

Usage: python scripts/check_branch_coverage.py REPORT.json FLOOR_PERCENT
"""

import json
import sys


def check(report_path: str, floor: float) -> int:
    with open(report_path) as handle:
        totals = json.load(handle)["totals"]
    branches = totals.get("num_branches")
    if not branches:
        print("No branch data in the report: run pytest with --cov and branch = true.")
        return 2
    covered = totals["covered_branches"]
    percent = 100 * covered / branches
    verdict = "ok" if percent >= floor else "BELOW THE FLOOR"
    print(f"Branch coverage {percent:.1f}% ({covered}/{branches}), floor {floor:g}%: {verdict}")
    return 0 if percent >= floor else 1


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    sys.exit(check(sys.argv[1], float(sys.argv[2])))
