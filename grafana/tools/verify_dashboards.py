"""Imports AnsiDeck's dashboards into a Grafana and runs every panel, annotation and variable
query through Grafana itself, so a broken query, a renamed metric or a view column that no
longer exists fails here instead of on someone's wall screen.

It creates (or replaces) two data sources, "AnsiDeck Prometheus" and "AnsiDeck database",
and imports the dashboards pointing at them, so run it against a throwaway or test Grafana.
Standard library only.

    python3 grafana/tools/verify_dashboards.py --grafana http://localhost:3000 \\
        --prometheus-url http://prometheus:9090 \\
        --postgres postgres:5432 --database ansideck --postgres-user grafana_ro \\
        --expect-data "Runs per day by status"

Passwords come from the environment: GRAFANA_PASSWORD (for --grafana-user, default admin)
and POSTGRES_PASSWORD (for --postgres-user). The URLs and addresses of the data sources are
as Grafana sees them. Exits 1 if any query fails, or a panel named with --expect-data
returns no data.
"""

import argparse
import base64
import json
import os
import pathlib
import re
import sys
import urllib.error
import urllib.request

PROM_UID = "ansideck-prometheus"
PG_UID = "ansideck-database"
PG_TYPE = "grafana-postgresql-datasource"
DEFAULT_DIR = pathlib.Path(__file__).resolve().parent.parent / "dashboards"


class Grafana:
    def __init__(self, url: str, user: str, password: str) -> None:
        self.url = url.rstrip("/")
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        self.headers = {"Authorization": f"Basic {token}", "Content-Type": "application/json"}

    def call(self, method: str, path: str, body: object = None) -> tuple[int, dict]:
        request = urllib.request.Request(
            self.url + path,
            method=method,
            headers=self.headers,
            data=None if body is None else json.dumps(body).encode(),
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.status, json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                return exc.code, json.loads(raw or b"{}")
            except ValueError:
                return exc.code, {"message": raw.decode(errors="replace")[:500]}


def ensure_datasource(grafana: Grafana, spec: dict) -> None:
    """Updates it in place when it exists: deleting and recreating a data source can leave the
    old one's database connections open, against the role's connection limit."""
    status, _ = grafana.call("GET", f"/api/datasources/uid/{spec['uid']}")
    if status == 200:
        status, body = grafana.call("PUT", f"/api/datasources/uid/{spec['uid']}", spec)
    else:
        status, body = grafana.call("POST", "/api/datasources", spec)
    if status != 200:
        sys.exit(f"could not create data source {spec['name']}: {status} {body}")


def substitute(text: str, projects: list[str]) -> str:
    """What Grafana's frontend does with the dashboard variables before it sends a query
    (the backend expands $__ macros itself)."""
    regex = "(" + "|".join(projects) + ")" if projects else "(-1)"
    csv = ",".join(projects) if projects else "-1"
    text = text.replace("${prometheus}", PROM_UID).replace("${postgres}", PG_UID)
    text = text.replace("${project:regex}", regex).replace("${project:csv}", csv)
    text = re.sub(r"\$\{project\}|\$project\b", csv, text)
    return text.replace("${ansideck_url}", "")


def run_query(
    grafana: Grafana, target: dict, projects: list[str], since: str, interval_ms: int
) -> tuple[str | None, int]:
    """(error or None, number of rows/points returned)."""
    query = json.loads(substitute(json.dumps(target), projects))
    query.setdefault("intervalMs", interval_ms)
    query.setdefault("maxDataPoints", 500)
    status, body = grafana.call(
        "POST", "/api/ds/query", {"queries": [query], "from": since, "to": "now"}
    )
    result = (body.get("results") or {}).get(query["refId"], {})
    if status != 200 or result.get("error"):
        return f"HTTP {status}: {result.get('error') or body.get('message') or body}", 0
    rows = 0
    for frame in result.get("frames", []):
        values = frame.get("data", {}).get("values", [])
        if values:
            rows += len(values[0])
    return None, rows


def project_ids(grafana: Grafana, dashboard: dict) -> list[str]:
    for variable in dashboard.get("templating", {}).get("list", []):
        if variable.get("name") == "project":
            target = {
                "refId": "V",
                "datasource": {"type": PG_TYPE, "uid": PG_UID},
                "rawSql": variable["query"],
                "format": "table",
                "rawQuery": True,
            }
            status, body = grafana.call(
                "POST", "/api/ds/query", {"queries": [target], "from": "now-7d", "to": "now"}
            )
            frame = body.get("results", {}).get("V", {}).get("frames", [{}])[0]
            fields = [f["name"] for f in frame.get("schema", {}).get("fields", [])]
            values = frame.get("data", {}).get("values", [])
            if status != 200 or "__value" not in fields:
                sys.exit(f"the project variable query failed: {status} {body}")
            return [str(v) for v in values[fields.index("__value")]] if values else []
    return []


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--grafana", required=True, help="Grafana base URL")
    parser.add_argument("--grafana-user", default="admin")
    parser.add_argument("--prometheus-url", required=True, help="as Grafana reaches it")
    parser.add_argument("--postgres", required=True, help="host:port as Grafana reaches it")
    parser.add_argument("--database", default="ansideck")
    parser.add_argument("--postgres-user", default="grafana_ro")
    parser.add_argument("--sslmode", default="disable")
    parser.add_argument("--dashboards", type=pathlib.Path, default=DEFAULT_DIR)
    parser.add_argument("--expect-data", action="append", default=[], metavar="PANEL_TITLE")
    parser.add_argument(
        "--since",
        default="now-7d",
        help="query time range start (a fresh Prometheus needs a short one, e.g. now-15m)",
    )
    parser.add_argument("--interval-ms", type=int, default=60_000, help="query step")
    parser.add_argument("--scrape-interval", default="30s", help="Prometheus' scrape interval")
    args = parser.parse_args()

    grafana = Grafana(args.grafana, args.grafana_user, os.environ.get("GRAFANA_PASSWORD", ""))
    ensure_datasource(
        grafana,
        {"uid": PROM_UID, "name": "AnsiDeck Prometheus", "type": "prometheus",
         "access": "proxy", "url": args.prometheus_url,
         "jsonData": {"timeInterval": args.scrape_interval}},
    )  # fmt: skip
    ensure_datasource(
        grafana,
        {"uid": PG_UID, "name": "AnsiDeck database", "type": PG_TYPE, "access": "proxy",
         "url": args.postgres, "user": args.postgres_user,
         "jsonData": {"database": args.database, "sslmode": args.sslmode,
                      "maxOpenConns": 4, "maxIdleConns": 2, "connMaxLifetime": 14400},
         "secureJsonData": {"password": os.environ.get("POSTGRES_PASSWORD", "")}},
    )  # fmt: skip

    failures: list[str] = []
    seen_titles: dict[str, int] = {}
    for path in sorted(args.dashboards.glob("*.json")):
        dashboard = json.loads(path.read_text())
        for variable in dashboard["templating"]["list"]:
            uid = {"prometheus": PROM_UID, "postgres": PG_UID}.get(variable["name"])
            if uid:
                variable["current"] = {"text": uid, "value": uid}
        status, body = grafana.call(
            "POST", "/api/dashboards/db", {"dashboard": dashboard, "overwrite": True}
        )
        if status != 200:
            failures.append(f"{path.name}: import failed: {status} {body}")
            continue
        print(f"{path.name}: imported as {body.get('url')}")
        projects = project_ids(grafana, dashboard)

        checks = [
            (panel["title"], target)
            for panel in dashboard["panels"]
            for target in panel.get("targets", [])
        ]
        checks += [
            (f"annotation: {a['name']}", {**a["target"], "datasource": a["datasource"]})
            for a in dashboard["annotations"]["list"]
            if "target" in a
        ]
        for title, target in checks:
            error, rows = run_query(grafana, target, projects, args.since, args.interval_ms)
            label = f"{dashboard['uid']} / {title} [{target['refId']}]"
            if error:
                failures.append(f"{label}: {error}")
                print(f"  FAIL  {label}: {error}")
            else:
                seen_titles[title] = seen_titles.get(title, 0) + rows
                print(f"  {'ok   ' if rows else 'empty'} {label}: {rows} rows")

    for title in args.expect_data:
        if not seen_titles.get(title):
            failures.append(f"expected data in panel {title!r}, got none")
    if failures:
        print("\n" + "\n".join(failures), file=sys.stderr)
        return 1
    print("every query ran" + (", and the expected panels have data" if args.expect_data else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
