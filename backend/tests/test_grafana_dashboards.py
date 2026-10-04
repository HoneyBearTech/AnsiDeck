"""The Grafana dashboards and alert examples shipped in grafana/: portable JSON, SQL that reads
only the analytics views (and runs, as a role that can read nothing else), and Prometheus
queries that only name metrics AnsiDeck exports. grafana/tools/verify_dashboards.py runs
them through a real Grafana in CI."""

import json
import re
from pathlib import Path

import pytest
import yaml
from sqlalchemy import text

from app import analytics
from app.db import get_engine, get_sessionmaker
from app.metrics import REGISTRY
from app.metrics_api import database_collector
from tests.test_analytics import ROLE, _drop_role

GRAFANA = Path(__file__).resolve().parents[2] / "grafana"
DASHBOARDS = sorted((GRAFANA / "dashboards").glob("*.json"))
ALERTS = GRAFANA / "provisioning" / "alerting" / "ansideck.example.yaml"
pytestmark = pytest.mark.skipif(not DASHBOARDS, reason="grafana/ is not next to backend/")

DATASOURCES = {"${prometheus}", "${postgres}", "-- Grafana --"}


def _load(path: Path) -> dict:
    return json.loads(path.read_text())


def _datasource_refs(node) -> list[dict]:
    if isinstance(node, dict):
        found = [node["datasource"]] if isinstance(node.get("datasource"), dict) else []
        return found + [ref for value in node.values() for ref in _datasource_refs(value)]
    if isinstance(node, list):
        return [ref for item in node for ref in _datasource_refs(item)]
    return []


def _queries(dashboard: dict) -> list[tuple[str, dict]]:
    """(where, target) for every panel, annotation and variable query."""
    found = [
        (f"{dashboard['uid']}/{panel['title']}", target)
        for panel in dashboard["panels"]
        for target in panel.get("targets", [])
    ]
    found += [
        (f"{dashboard['uid']}/annotation {a['name']}", a["target"])
        for a in dashboard["annotations"]["list"]
        if "target" in a
    ]
    found += [
        (f"{dashboard['uid']}/variable {v['name']}", {"rawSql": v["query"]})
        for v in dashboard["templating"]["list"]
        if v["type"] == "query"
    ]
    return found


def _sql() -> list[tuple[str, str]]:
    return [
        (where, t["rawSql"])
        for d in map(_load, DASHBOARDS)
        for where, t in _queries(d)
        if "rawSql" in t
    ]


def _promql() -> list[tuple[str, str]]:
    found = [
        (where, t["expr"])
        for d in map(_load, DASHBOARDS)
        for where, t in _queries(d)
        if "expr" in t
    ]
    for group in yaml.safe_load(ALERTS.read_text())["groups"]:
        for rule in group["rules"]:
            for query in rule["data"]:
                if "expr" in query["model"]:
                    found.append((f"alert {rule['uid']}", query["model"]["expr"]))
    return found


def test_the_dashboards_are_portable() -> None:
    uids = set()
    for path in DASHBOARDS:
        dashboard = _load(path)
        assert path.stem == dashboard["uid"] and dashboard["uid"].startswith("ansideck-")
        uids.add(dashboard["uid"])
        assert dashboard.get("id") is None  # Grafana assigns its own
        assert "__inputs" not in dashboard  # those only work for a UI import
        refs = _datasource_refs(dashboard)
        assert refs and {ref["uid"] for ref in refs} <= DATASOURCES, path.name
        variables = {v["name"]: v for v in dashboard["templating"]["list"]}
        assert variables["prometheus"]["query"] == "prometheus"
        assert variables["postgres"]["query"] == "grafana-postgresql-datasource"
        titles = [p["title"] for p in dashboard["panels"] if p["type"] != "row"]
        assert len(titles) == len(set(titles)), path.name
        ids = [p["id"] for p in dashboard["panels"]]
        assert len(ids) == len(set(ids)), path.name
    assert len(uids) == len(DASHBOARDS) == 3


def test_sql_reads_only_the_analytics_views() -> None:
    queries = _sql()
    assert len(queries) > 20
    for where, query in queries:
        without_extract = re.sub(r"extract\([^)]*\)", "", query, flags=re.IGNORECASE)
        tables = re.findall(r"\b(?:FROM|JOIN)\s+([a-z_.]+)", without_extract, re.IGNORECASE)
        assert tables, where
        assert all(t.startswith("analytics.") for t in tables), (where, tables)


def _as_plain_sql(query: str) -> str:
    """Grafana's macros and the dashboard variables, as Grafana would expand them."""
    query = re.sub(
        r"\$__timeFilter\(([a-z_]+)\)",
        r"(\1 BETWEEN now() - interval '7 days' AND now())",
        query,
    )
    query = re.sub(
        r"\$__timeGroupAlias\(([a-z_]+), [^)]+\)",
        r"date_trunc('hour', \1) AS time",
        query,
    )
    query = query.replace("$project", "1, 2")
    assert "$" not in query, query
    return query


def test_every_dashboard_query_runs_as_a_read_only_role(client) -> None:
    with get_engine().begin() as conn:
        _drop_role(conn, ROLE)
        conn.execute(text(f"CREATE ROLE {ROLE} NOLOGIN"))
    db = get_sessionmaker()()
    try:
        assert analytics.grant(db, ROLE).ok
        with get_engine().connect() as conn:
            conn.execute(text(f"SET ROLE {ROLE}"))
            for where, query in _sql():
                try:
                    conn.execute(text(_as_plain_sql(query).replace(":", r"\:"))).all()
                except Exception as exc:  # noqa: BLE001 - report which panel
                    pytest.fail(f"{where}: {exc}")
            conn.rollback()
    finally:
        db.close()
        with get_engine().begin() as conn:
            _drop_role(conn, ROLE)


def _exported_names() -> set[str]:
    database_collector.invalidate()
    names = set()
    for family in REGISTRY.collect():
        names.add(family.name)
        names.update(sample.name for sample in family.samples)
        # A labelled family has no samples until used: add the names it will have.
        suffixes = {"counter": ["_total"], "histogram": ["_bucket", "_count", "_sum"]}
        names.update(family.name + suffix for suffix in suffixes.get(family.type, []))
    return names


def test_prometheus_queries_name_only_metrics_ansideck_exports(client) -> None:
    exported = _exported_names()
    assert "ansideck_runs" in exported  # the database gauges were collected
    queries = _promql()
    assert len(queries) > 20
    for where, expr in queries:
        for name in re.findall(r"\bansideck_[a-z_]+", expr):
            assert name in exported, (where, name)
