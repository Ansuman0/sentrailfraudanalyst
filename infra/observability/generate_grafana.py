"""Generates the Grafana dashboard and alert rules (run from the repo root). Output is committed; this is a build helper."""
import json
from pathlib import Path
import yaml

root = Path(__file__).resolve().parent / "grafana"
A = '{compose_service="api"'
DS = {"type": "loki", "uid": "loki"}
EXPR_DS = {"type": "__expr__", "uid": "__expr__"}


def q(expr, ref="A", legend=""):
    return {"refId": ref, "datasource": DS, "expr": expr, "legendFormat": legend, "queryType": "range"}


pid = 0


def _id():
    global pid
    pid += 1
    return pid


def ts(title, targets, x, y, w=12, h=8, unit="short"):
    return {"id": _id(), "type": "timeseries", "title": title, "datasource": DS, "targets": targets,
            "gridPos": {"x": x, "y": y, "w": w, "h": h}, "fieldConfig": {"defaults": {"unit": unit}, "overrides": []}}


def logs(title, expr, y):
    return {"id": _id(), "type": "logs", "title": title, "datasource": DS,
            "targets": [{"refId": "A", "datasource": DS, "expr": expr, "queryType": "range"}],
            "gridPos": {"x": 0, "y": y, "w": 24, "h": 10},
            "options": {"showTime": True, "wrapLogMessage": True, "enableLogDetails": True, "sortOrder": "Descending"}}


def row(title, y):
    return {"id": _id(), "type": "row", "title": title, "collapsed": False, "gridPos": {"x": 0, "y": y, "w": 24, "h": 1}}


def sel(extra=""):
    return A + (", " + extra if extra else "") + "}"


req = sel('event="api_request"') + " | json"

panels = [
    row("Backend", 0),
    ts("Requests per minute", [q(f"sum(count_over_time({sel('event=\"api_request\"')} [1m]))", legend="requests")], 0, 1),
    ts("Errors per minute (4xx / 5xx)", [
        q(f"sum(count_over_time({req} | status_code >= 400 | status_code < 500 [1m]))", "A", "4xx"),
        q(f"sum(count_over_time({req} | status_code >= 500 [1m]))", "B", "5xx")], 12, 1),
    ts("Latency p95 by route (ms)", [q(f"quantile_over_time(0.95, {req} | unwrap duration_ms [5m]) by (path)", legend="{{path}}")], 0, 9, unit="ms"),
    ts("Failed sign-ins and second-factor failures", [q(
        f"sum by (event) (count_over_time({sel('event=~\"audit_login_failed|audit_mfa_failed|audit_refresh_token_reuse_detected\"')} [5m]))",
        legend="{{event}}")], 12, 9),
    row("External services", 17),
    ts("Calls per service", [q(
        f"sum by (target_service) (count_over_time({sel('event=~\"external_api_request|external_api_failure\"')} | json [5m]))",
        legend="{{target_service}}")], 0, 18),
    ts("Failures per service", [q(
        f"sum by (target_service, error_category) (count_over_time({sel('event=\"external_api_failure\"')} | json [5m]))",
        legend="{{target_service}} {{error_category}}")], 12, 18),
    ts("External latency p95 (ms)", [q(
        f"quantile_over_time(0.95, {sel('event=\"external_api_request\"')} | json | unwrap duration_ms [5m]) by (target_service)",
        legend="{{target_service}}")], 0, 26, unit="ms"),
    row("AI", 34),
    ts("AI requests by outcome", [
        q(f"sum(count_over_time({sel('event=\"ai_request_completed\"')} [5m]))", "A", "completed"),
        q(f"sum(count_over_time({sel('event=\"ai_request_failed\"')} [5m]))", "B", "failed")], 0, 35),
    ts("AI latency p95 (ms) by model", [q(
        f"quantile_over_time(0.95, {sel('event=\"ai_request_completed\"')} | json | unwrap duration_ms [15m]) by (model)",
        legend="{{model}}")], 12, 35, unit="ms"),
    row("Find a request", 43),
    logs("Logs for the request / trace id in the variable above (.* shows everything)",
         f'{sel()} | json | request_id=~"$request_id" or trace_id=~"$request_id"', 44),
    logs("Warnings and errors", sel('level=~"WARNING|ERROR|CRITICAL"'), 54),
]
dash = {"uid": "sentrail-overview", "title": "Sentrail overview", "schemaVersion": 39, "version": 1, "editable": False,
        "refresh": "30s", "time": {"from": "now-6h", "to": "now"}, "tags": ["sentrail"],
        "templating": {"list": [{"name": "request_id", "type": "textbox", "label": "request / trace id", "query": ".*",
                                 "current": {"text": ".*", "value": ".*"}}]},
        "panels": panels}
(root / "dashboards" / "sentrail-overview.json").write_text(json.dumps(dash, indent=1), encoding="utf-8")


def rule(uid, title, expr, window, thr, sev, summary, action, for_="0s"):
    return {"uid": uid, "title": title, "condition": "C", "for": for_, "noDataState": "OK", "execErrState": "Error",
            "labels": {"severity": sev}, "annotations": {"summary": summary, "action": action},
            "data": [
                {"refId": "A", "relativeTimeRange": {"from": window, "to": 0}, "datasourceUid": "loki",
                 "model": {"refId": "A", "expr": expr, "queryType": "instant", "datasource": DS}},
                {"refId": "B", "datasourceUid": "__expr__",
                 "model": {"refId": "B", "type": "reduce", "expression": "A", "reducer": "last", "datasource": EXPR_DS}},
                {"refId": "C", "datasourceUid": "__expr__",
                 "model": {"refId": "C", "type": "threshold", "expression": "B", "datasource": EXPR_DS,
                           "conditions": [{"evaluator": {"type": "gt", "params": [thr]}}]}}]}


rules = [
    rule("sentrail-5xx", "API server errors", f"sum(count_over_time({req} | status_code >= 500 [5m]))", 300, 5, "critical",
         "More than 5 responses with status 500 or above in 5 minutes",
         "Open the dashboard, look at Warnings and errors, take the request_id of a 5xx and read its log lines"),
    rule("sentrail-latency", "API latency high",
         f'quantile_over_time(0.95, {req} | path != "/screen" | unwrap duration_ms [5m])', 300, 2000, "warning",
         "p95 request latency above 2 seconds for 5 minutes (screening excluded)",
         "Check Latency by route, then External services (slow chain APIs) and the database", "5m"),
    rule("sentrail-ready", "Readiness probe failing",
         f'sum(count_over_time({req} | path="/readyz" | status_code >= 400 [5m]))', 300, 0, "critical",
         "/readyz returned an error: the database or another required dependency is unreachable",
         "Check docker compose ps and the postgres logs; verify DATABASE_URL"),
    rule("sentrail-external", "External service failures",
         f"sum(count_over_time({sel('event=\"external_api_failure\"')} [5m]))", 300, 3, "warning",
         "More than 3 failed calls to chain APIs or the OFAC list in 5 minutes",
         "See Failures per service. While the OFAC list can't load, screening holds transfers by design"),
    rule("sentrail-ai", "AI requests failing",
         f"sum(count_over_time({sel('event=\"ai_request_failed\"')} [10m]))", 600, 3, "warning",
         "More than 3 failed AI requests in 10 minutes",
         "Check that Ollama is running and the model is pulled (docker compose ps)"),
    rule("sentrail-logins", "Sign-in failures spike",
         f"sum(count_over_time({sel('event=~\"audit_login_failed|audit_mfa_failed\"')} [5m]))", 300, 20, "warning",
         "More than 20 failed sign-ins or second-factor checks in 5 minutes",
         "Possible password guessing: review the audit log of the affected organizations; accounts lock after repeated failures"),
]
alerts = {"apiVersion": 1, "groups": [{"orgId": 1, "name": "sentrail", "folder": "Sentrail", "interval": "1m", "rules": rules}]}
(root / "provisioning" / "alerting" / "rules.yaml").write_text(yaml.safe_dump(alerts, sort_keys=False, width=200), encoding="utf-8")
print("panels", len(panels), "rules", len(rules))
