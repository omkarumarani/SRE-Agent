"""
main.py — sre-agent FastAPI application.

Endpoints
─────────
POST /alert                      Alertmanager webhook receiver
GET  /incidents                  List incidents (paginated, filterable by status)
GET  /incidents/{id}             Full detail + timeline + evidence + Grafana links + PromQL list
GET  /incidents/{id}/evidence    Raw evidence packet JSON
GET  /health                     Liveness / readiness probe
GET  /metrics                    Prometheus text exposition
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import uvicorn
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse, PlainTextResponse
from prometheus_client import Counter, Gauge, generate_latest, CONTENT_TYPE_LATEST

import db
import evidence_collector as ec
import grafana_links as gl
import github_issue_tool as git_issue
import llm_provider as lp
import notifier
import prometheus_tool as pt
from models import (
    AlertmanagerWebhook,
    AlertReceiveResponse,
    DashboardLink,
    ExploreLink,
    GrafanaLinks,
    HealthResponse,
    IncidentDetail,
    IncidentSummary,
    LLMAnalysis,
    PromQLRef,
    TimelineEntry,
)

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
log = logging.getLogger("sre_agent")

# ── Prometheus metrics ────────────────────────────────────────────────────────

ALERTS_RECEIVED = Counter(
    "sre_agent_alerts_received_total",
    "Total number of individual alerts received from Alertmanager",
    ["alertname", "status"],
)
INCIDENTS_TOTAL = Counter(
    "sre_agent_incidents_total",
    "Total number of incident records created",
    ["alertname", "severity"],
)
INCIDENTS_OPEN = Gauge(
    "sre_agent_incidents_open",
    "Current number of open incidents",
)
WEBHOOK_ERRORS = Counter(
    "sre_agent_webhook_errors_total",
    "Total number of errors while processing webhook payloads",
)
EVIDENCE_COLLECTED = Counter(
    "sre_agent_evidence_collected_total",
    "Total number of evidence packets collected",
    ["status"],
)
EMAILS_SENT = Counter(
    "sre_agent_emails_sent_total",
    "Total notification emails attempted",
    ["status"],   # "ok" | "error"
)

SCHEDULED_SCANS = Counter(
    "sre_agent_scheduled_scans_total",
    "Total number of scheduled health scan runs",
    ["status"],  # ok | error
)


# ── Scheduled scan config ────────────────────────────────────────────────────

SCAN_INTERVAL_MIN = int(os.environ.get("SCAN_INTERVAL_MIN", "5"))
FLAKY_ERROR_RATE_THRESHOLD = float(os.environ.get("FLAKY_ERROR_RATE_THRESHOLD", "0.05"))
RESTARTS_5M_THRESHOLD = float(os.environ.get("RESTARTS_5M_THRESHOLD", "1.0"))

_scheduler: AsyncIOScheduler | None = None


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _scheduler
    await db.init_db()
    open_rows = await db.list_incidents(limit=1000, status="open")
    INCIDENTS_OPEN.set(len(open_rows))

    _scheduler = AsyncIOScheduler(timezone="UTC")
    _scheduler.add_job(
        _run_scheduled_scan,
        trigger="interval",
        minutes=max(1, SCAN_INTERVAL_MIN),
        id="scheduled-health-scan",
        coalesce=True,
        max_instances=1,
        misfire_grace_time=60,
    )
    _scheduler.start()

    log.info(
        "sre-agent ready — %d open incidents  "
        "prometheus=%s  grafana=%s  evidence_dir=%s  "
        "smtp=%s:%s  email_enabled=%s  scan_interval_min=%s",
        len(open_rows),
        pt.PROMETHEUS_URL, gl.GRAFANA_URL, ec.EVIDENCE_DIR,
        notifier.SMTP_HOST, notifier.SMTP_PORT, notifier.EMAIL_ENABLED, SCAN_INTERVAL_MIN,
    )
    yield
    if _scheduler:
        _scheduler.shutdown(wait=False)
        _scheduler = None
    await pt.close_client()
    log.info("sre-agent shutting down")


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="sre-agent",
    description="AI-ready SRE incident receiver, evidence collector, and store",
    version="2.2.0",
    lifespan=lifespan,
)


# ── Scheduled health scan ────────────────────────────────────────────────────

async def _run_scheduled_scan() -> None:
    """
    Runs every 5 minutes (configurable) and creates incidents without
    Alertmanager when health thresholds are breached.
    """
    try:
        created = 0
        created += await _scan_flaky_error_rate()
        created += await _scan_container_restart_rate()
        SCHEDULED_SCANS.labels(status="ok").inc()
        if created:
            log.warning("Scheduled scan created %d synthetic incident(s)", created)
    except Exception as exc:
        SCHEDULED_SCANS.labels(status="error").inc()
        log.exception("Scheduled scan failed: %s", exc)


async def _scan_flaky_error_rate() -> int:
    promql = pt.render(pt.TEMPLATES["flaky_error_rate"], window="5m")
    resp = await pt.query_instant(promql)
    value = _max_vector_value(resp)
    if value is None or value <= FLAKY_ERROR_RATE_THRESHOLD:
        return 0

    alertname = "ScheduledFlakyApiHighErrorRate"
    severity = "warning"
    service = "flaky-api"
    container = "flaky-api"
    summary = (
        f"Scheduled scan detected flaky_api error rate above threshold: "
        f"value={value:.4f} threshold={FLAKY_ERROR_RATE_THRESHOLD:.4f}"
    )
    labels = {
        "source": "scheduled_scan",
        "check": "flaky_api_error_rate",
        "alertname": alertname,
        "severity": severity,
        "service": service,
        "container_name": container,
    }
    annotations = {
        "summary": summary,
        "promql": promql,
    }
    fingerprint = f"scheduled_scan:flaky_api_error_rate:{container}"
    return await _create_synthetic_incident(
        fingerprint=fingerprint,
        alertname=alertname,
        severity=severity,
        service=service,
        container=container,
        summary=summary,
        labels=labels,
        annotations=annotations,
    )


async def _scan_container_restart_rate() -> int:
    promql = "topk(1, increase(container_restart_count{name!='',image!=''}[5m]))"
    resp = await pt.query_instant(promql)
    top = _top_result(resp)
    if not top:
        return 0

    value = top["value"]
    if value <= RESTARTS_5M_THRESHOLD:
        return 0

    metric = top.get("metric", {})
    container = (
        metric.get("name")
        or metric.get("container")
        or metric.get("container_name")
        or "unknown"
    )
    alertname = "ScheduledContainerHighRestartRate"
    severity = "warning"
    service = metric.get("pod", "") or metric.get("job", "") or "container-runtime"
    summary = (
        f"Scheduled scan detected restart increase above threshold: "
        f"container={container} value={value:.2f} threshold={RESTARTS_5M_THRESHOLD:.2f}"
    )
    labels = {
        "source": "scheduled_scan",
        "check": "container_restart_rate",
        "alertname": alertname,
        "severity": severity,
        "service": service,
        "container_name": container,
    }
    annotations = {
        "summary": summary,
        "promql": promql,
    }
    fingerprint = f"scheduled_scan:container_restart_rate:{container}"
    return await _create_synthetic_incident(
        fingerprint=fingerprint,
        alertname=alertname,
        severity=severity,
        service=service,
        container=container,
        summary=summary,
        labels=labels,
        annotations=annotations,
    )


def _max_vector_value(resp: dict) -> float | None:
    try:
        results = resp.get("data", {}).get("result", [])
        vals = [float(r["value"][1]) for r in results if "value" in r]
        return max(vals) if vals else None
    except Exception:
        return None


def _top_result(resp: dict) -> dict | None:
    try:
        results = resp.get("data", {}).get("result", [])
        if not results:
            return None
        first = results[0]
        return {
            "metric": first.get("metric", {}),
            "value": float(first.get("value", [0, 0])[1]),
        }
    except Exception:
        return None


async def _create_synthetic_incident(
    fingerprint: str,
    alertname: str,
    severity: str,
    service: str,
    container: str,
    summary: str,
    labels: dict[str, str],
    annotations: dict[str, str],
) -> int:
    alert_hash = db.compute_hash(fingerprint, labels)
    existing = await db.get_incident_by_hash(alert_hash)
    if existing:
        await db.add_timeline_entry(
            existing["id"],
            event="scheduled_scan_re_detected",
            detail=f"Scheduled scan still breaching threshold. summary={summary}",
        )
        return 0

    incident_id = await db.create_incident(
        alertname=alertname,
        severity=severity,
        service=service,
        container_name=container,
        summary=summary,
        labels=labels,
        annotations=annotations,
        raw_alert_hash=alert_hash,
    )
    await db.add_timeline_entry(
        incident_id,
        event="scheduled_scan_incident_opened",
        detail=f"Synthetic incident created from scheduled scan. fingerprint={fingerprint}",
    )
    INCIDENTS_TOTAL.labels(alertname=alertname, severity=severity).inc()
    INCIDENTS_OPEN.inc()

    asyncio.create_task(
        _background_collect(
            incident_id=incident_id,
            alertname=alertname,
            severity=severity,
            service=service,
            container=container,
            summary=summary,
            created_at=datetime.now(timezone.utc).isoformat(),
            labels=dict(labels),
        )
    )
    return 1


# ── Background task: evidence + email ─────────────────────────────────────────

async def _background_collect(
    incident_id: int,
    alertname:   str,
    severity:    str,
    service:     str,
    container:   str,
    summary:     str,
    created_at:  str,
    labels:      dict[str, str],
) -> None:
    """
    Runs after a new incident is created (fire-and-forget via asyncio.create_task):
      1. Collect evidence from Prometheus; write JSON; update DB row.
      2. Build Grafana links from the collected PromQL queries.
      3. Send notification email containing evidence stats + Grafana links.

    Each step is individually try/excepted so a failure in one never
    prevents the others from running.
    """
    # ── 1. Evidence ───────────────────────────────────────────────────────────
    evidence: dict | None = None
    try:
        path = await ec.collect(
            incident_id=incident_id,
            alertname=alertname,
            container=container,
            service=service,
            labels=labels,
        )
        if path:
            await db.update_evidence_path(incident_id, path)
            EVIDENCE_COLLECTED.labels(status="ok").inc()
            evidence = ec.load_packet(incident_id)
        else:
            EVIDENCE_COLLECTED.labels(status="error").inc()
    except Exception as exc:
        log.exception("Evidence collection failed for incident #%d: %s", incident_id, exc)
        EVIDENCE_COLLECTED.labels(status="error").inc()

    # ── 2. Grafana links ──────────────────────────────────────────────────────
    grafana_raw: dict | None = None
    try:
        dt = datetime.fromisoformat(created_at)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        promql_queries = evidence.get("promql_queries", []) if evidence else []
        grafana_raw = gl.build_links(
            incident_id=incident_id,
            created_at=dt,
            container=container,
            service=service,
            promql_queries=promql_queries,
        )
    except Exception as exc:
        log.warning("Grafana link build failed for incident #%d: %s", incident_id, exc)

    # ── 3. LLM analysis (sanitized + aggregated evidence only) ───────────────
    llm_analysis: dict | None = None
    try:
        llm_analysis = await lp.generate_incident_analysis(
            incident_id=incident_id,
            alertname=alertname,
            severity=severity,
            service=service,
            container=container,
            summary=summary,
            labels=labels,
            evidence_packet=evidence,
        )
        if llm_analysis:
            await db.update_llm_response(incident_id, json.dumps(llm_analysis))
            await db.add_timeline_entry(
                incident_id,
                event="llm_analysis_generated",
                detail=(
                    f"LLM analysis saved using provider={llm_analysis.get('provider')} "
                    f"model={llm_analysis.get('model')}"
                ),
            )
    except Exception as exc:
        log.exception("LLM analysis failed for incident #%d: %s", incident_id, exc)
        await db.add_timeline_entry(
            incident_id,
            event="llm_analysis_failed",
            detail=f"LLM analysis failed: {exc}",
        )

    # ── 4. GitHub issue (optional) ───────────────────────────────────────────
    try:
        issue_url = await git_issue.create_incident_issue(
            incident_id=incident_id,
            alertname=alertname,
            container=container,
            summary=summary,
            evidence_packet=evidence,
            grafana_links=grafana_raw,
            llm_analysis=llm_analysis,
        )
        if issue_url:
            await db.update_github_issue_url(incident_id, issue_url)
            await db.add_timeline_entry(
                incident_id,
                event="github_issue_created",
                detail=f"GitHub issue created: {issue_url}",
            )
    except Exception as exc:
        log.exception("GitHub issue creation failed for incident #%d: %s", incident_id, exc)
        await db.add_timeline_entry(
            incident_id,
            event="github_issue_failed",
            detail=f"GitHub issue creation failed: {exc}",
        )

    # ── 5. Email ──────────────────────────────────────────────────────────────
    try:
        await notifier.notify_incident_opened(
            incident_id=incident_id,
            alertname=alertname,
            severity=severity,
            service=service,
            container_name=container,
            summary=summary,
            created_at=created_at,
            labels=labels,
            evidence_packet=evidence,
            grafana_links=grafana_raw,
        )
        EMAILS_SENT.labels(status="ok").inc()
    except Exception as exc:
        log.exception("Email notification failed for incident #%d: %s", incident_id, exc)
        EMAILS_SENT.labels(status="error").inc()


# ── POST /alert ───────────────────────────────────────────────────────────────

@app.post(
    "/alert",
    response_model=AlertReceiveResponse,
    summary="Alertmanager webhook receiver",
)
async def receive_alert(payload: AlertmanagerWebhook):
    """
    Accepts the Alertmanager webhook JSON body.
    For each alert: deduplicates, opens/updates incident, triggers
    background evidence collection + email notification for new incidents.
    """
    incidents_created = 0
    incidents_updated = 0

    for alert in payload.alerts:
        try:
            alertname      = alert.labels.get("alertname", "unknown")
            severity       = alert.labels.get("severity", "")
            service        = alert.labels.get("service", "")
            container_name = alert.labels.get("container_name", "")
            summary        = alert.annotations.get("summary", alertname)

            alert_hash = db.compute_hash(alert.fingerprint, alert.labels)
            ALERTS_RECEIVED.labels(alertname=alertname, status=alert.status).inc()

            existing = await db.get_incident_by_hash(alert_hash)

            if alert.status == "resolved":
                if existing:
                    await db.update_incident_status(existing["id"], "resolved")
                    await db.add_timeline_entry(
                        existing["id"],
                        event="alert_resolved",
                        detail=f"Alertmanager reported resolved — fingerprint={alert.fingerprint}",
                    )
                    INCIDENTS_OPEN.dec()
                    incidents_updated += 1
                    log.info("Incident #%d resolved  alertname=%s", existing["id"], alertname)
                else:
                    incident_id = await db.create_incident(
                        alertname=alertname, severity=severity, service=service,
                        container_name=container_name, summary=summary,
                        labels=alert.labels, annotations=alert.annotations,
                        raw_alert_hash=alert_hash,
                    )
                    await db.update_incident_status(incident_id, "resolved")
                    await db.add_timeline_entry(
                        incident_id,
                        event="alert_received_resolved",
                        detail="Received in resolved state — no prior open incident found.",
                    )
                    INCIDENTS_TOTAL.labels(alertname=alertname, severity=severity).inc()
                    incidents_created += 1

            else:  # firing
                if existing:
                    await db.add_timeline_entry(
                        existing["id"],
                        event="alert_re_fired",
                        detail=f"Alert still firing — re-notified. summary={summary}",
                    )
                    incidents_updated += 1
                    log.info("Incident #%d still open  alertname=%s", existing["id"], alertname)
                else:
                    incident_id = await db.create_incident(
                        alertname=alertname, severity=severity, service=service,
                        container_name=container_name, summary=summary,
                        labels=alert.labels, annotations=alert.annotations,
                        raw_alert_hash=alert_hash,
                    )
                    await db.add_timeline_entry(
                        incident_id,
                        event="incident_opened",
                        detail=(
                            f"New incident created from firing alert. "
                            f"alertname={alertname}  severity={severity}  "
                            f"fingerprint={alert.fingerprint}"
                        ),
                    )
                    INCIDENTS_TOTAL.labels(alertname=alertname, severity=severity).inc()
                    INCIDENTS_OPEN.inc()
                    incidents_created += 1
                    log.info("Incident #%d created  alertname=%s", incident_id, alertname)

                    # Capture the alert start time to anchor the Grafana time window
                    incident_created_at = (
                        alert.startsAt.isoformat()
                        if alert.startsAt
                        else datetime.now(timezone.utc).isoformat()
                    )
                    asyncio.create_task(
                        _background_collect(
                            incident_id=incident_id,
                            alertname=alertname,
                            severity=severity,
                            service=service,
                            container=container_name,
                            summary=summary,
                            created_at=incident_created_at,
                            labels=dict(alert.labels),
                        )
                    )

        except Exception as exc:
            WEBHOOK_ERRORS.inc()
            log.exception("Error processing alert %s: %s", alert.labels.get("alertname"), exc)

    return AlertReceiveResponse(
        received=len(payload.alerts),
        incidents_created=incidents_created,
        incidents_updated=incidents_updated,
    )


# ── GET /incidents ────────────────────────────────────────────────────────────

@app.get(
    "/incidents",
    response_model=list[IncidentSummary],
    summary="List incidents",
)
async def list_incidents(
    status: str | None = Query(default=None,
                                description="Filter: open | resolved | acknowledged"),
    limit:  int        = Query(default=50,  ge=1, le=200),
    offset: int        = Query(default=0,   ge=0),
):
    rows = await db.list_incidents(limit=limit, offset=offset, status=status)
    return [
        IncidentSummary(
            id=r["id"],
            created_at=r["created_at"],
            updated_at=r["updated_at"],
            status=r["status"],
            alertname=r["alertname"],
            severity=r["severity"],
            service=r["service"],
            container_name=r["container_name"],
            summary=r["summary"],
            evidence_path=r.get("evidence_path", ""),
            github_issue_url=r.get("github_issue_url", ""),
        )
        for r in rows
    ]


# ── Helpers: Grafana links + PromQL refs ──────────────────────────────────────

def _parse_created_at(raw: str | datetime) -> datetime:
    if isinstance(raw, datetime):
        dt = raw
    else:
        dt = datetime.fromisoformat(raw)
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def _build_grafana_links(row: dict, packet: dict | None) -> GrafanaLinks | None:
    try:
        raw = gl.build_links(
            incident_id=row["id"],
            created_at=_parse_created_at(row["created_at"]),
            container=row.get("container_name", ""),
            service=row.get("service", ""),
            promql_queries=packet.get("promql_queries", []) if packet else [],
        )
        return GrafanaLinks(
            time_window=raw["time_window"],
            explore=[ExploreLink(**e) for e in raw["explore"]],
            dashboards=[DashboardLink(**d) for d in raw["dashboards"]],
        )
    except Exception as exc:
        log.warning("Grafana links failed for incident #%s: %s", row.get("id"), exc)
        return None


def _build_promql_refs(packet: dict | None) -> list[PromQLRef]:
    if not packet:
        return []
    refs = []
    for q in packet.get("promql_queries", []):
        try:
            refs.append(PromQLRef(
                metric_key=q.get("metric_key", ""),
                label=q.get("label", q.get("metric_key", "")),
                promql=q.get("promql", ""),
                query_type=q.get("query_type", "range"),
                window_minutes=q.get("window_minutes"),
            ))
        except Exception:
            pass
    return refs


def _build_llm_analysis(row: dict) -> LLMAnalysis | None:
    raw = row.get("llm_response", "")
    if not raw:
        return None
    try:
        data = json.loads(raw) if isinstance(raw, str) else raw
        return LLMAnalysis(**data)
    except Exception as exc:
        log.warning("Failed to parse llm_response for incident #%s: %s", row.get("id"), exc)
        return None


# ── GET /incidents/{id} ───────────────────────────────────────────────────────

@app.get(
    "/incidents/{incident_id}",
    response_model=IncidentDetail,
    summary="Full incident detail + timeline + evidence + Grafana links + PromQL queries",
)
async def get_incident(incident_id: int):
    """
    Returns the complete incident record including:

    - **timeline** — ordered log of every event
    - **evidence** — raw metric data collected from Prometheus at incident open time
    - **grafana_links.explore** — one Grafana Explore deep-link per PromQL query,
      time-ranged 30 min before → 15 min after the incident opened
    - **grafana_links.dashboards** — relevant dashboard links with variables pre-filled
    - **promql_queries** — every PromQL expression run during evidence collection
    """
    row = await db.get_incident(incident_id)
    if not row:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    timeline_rows = await db.get_timeline(incident_id)
    timeline = [
        TimelineEntry(
            id=t["id"],
            incident_id=t["incident_id"],
            created_at=t["created_at"],
            event=t["event"],
            detail=t["detail"],
        )
        for t in timeline_rows
    ]

    evidence_data: dict | None = None
    evidence_path = row.get("evidence_path", "")
    if evidence_path:
        evidence_data = ec.load_packet(incident_id)

    return IncidentDetail(
        id=row["id"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        status=row["status"],
        alertname=row["alertname"],
        severity=row["severity"],
        service=row["service"],
        container_name=row["container_name"],
        summary=row["summary"],
        evidence_path=evidence_path,
        github_issue_url=row.get("github_issue_url", ""),
        labels=json.loads(row["labels"]),
        annotations=json.loads(row["annotations"]),
        raw_alert_hash=row["raw_alert_hash"],
        timeline=timeline,
        evidence=evidence_data,
        grafana_links=_build_grafana_links(row, evidence_data),
        promql_queries=_build_promql_refs(evidence_data),
        llm_analysis=_build_llm_analysis(row),
    )


# ── GET /incidents/{id}/evidence ──────────────────────────────────────────────

@app.get(
    "/incidents/{incident_id}/evidence",
    summary="Raw evidence packet JSON",
    response_class=JSONResponse,
)
async def get_evidence(incident_id: int):
    """Returns the raw evidence JSON. HTTP 202 if collection still in progress."""
    row = await db.get_incident(incident_id)
    if not row:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    evidence_path = row.get("evidence_path", "")
    if not evidence_path:
        raise HTTPException(
            status_code=202,
            detail="Evidence collection in progress — retry in a few seconds",
        )
    packet = ec.load_packet(incident_id)
    if packet is None:
        raise HTTPException(status_code=404, detail=f"Evidence file not found at {evidence_path}")
    return JSONResponse(content=packet)


# ── GET /health ───────────────────────────────────────────────────────────────

@app.get("/health", response_model=HealthResponse, summary="Liveness probe")
async def health():
    try:
        total     = await db.count_incidents()
        db_status = "ok"
    except Exception as exc:
        log.error("DB health check failed: %s", exc)
        db_status = f"error: {exc}"
        total     = -1

    return HealthResponse(
        status="ok" if db_status == "ok" else "degraded",
        db=db_status,
        incidents_total=total,
        prometheus_url=pt.PROMETHEUS_URL,
        grafana_url=gl.GRAFANA_URL,
        evidence_dir=ec.EVIDENCE_DIR,
        smtp_host=notifier.SMTP_HOST,
        smtp_port=notifier.SMTP_PORT,
        email_enabled=notifier.EMAIL_ENABLED,
    )


# ── GET /metrics ──────────────────────────────────────────────────────────────

@app.get("/metrics", include_in_schema=False)
async def metrics():
    return PlainTextResponse(
        content=generate_latest().decode("utf-8"),
        media_type=CONTENT_TYPE_LATEST,
    )


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info", access_log=True)
