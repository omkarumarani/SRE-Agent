"""
evidence_collector.py — EvidenceCollector for sre-agent.

When a new incident is created, EvidenceCollector:
  1. Fetches a battery of PromQL queries relevant to the alerting container.
  2. Adds flaky-api application metrics if the service label matches.
  3. Assembles an "evidence packet" capturing:
       - collection metadata
       - raw range-query series (last 15 m or 1 h depending on metric)
       - human-readable summaries (min/max/avg/last)
       - promql_queries: list of every query run (for Grafana Explore links)
       - any non-fatal collection errors
  4. Writes the packet as JSON to  {EVIDENCE_DIR}/incident_{id}.json
  5. Stores the path + a short text digest in the incident_timeline table.

Configuration (env vars):
  PROMETHEUS_URL    default: http://prometheus:9090
  EVIDENCE_DIR      default: /data/evidence
  COLLECT_TIMEOUT   default: 30  (seconds — whole collection budget)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import prometheus_tool as pt
import db

log = logging.getLogger("sre_agent.evidence_collector")

EVIDENCE_DIR    = os.environ.get("EVIDENCE_DIR",    "/data/evidence")
COLLECT_TIMEOUT = float(os.environ.get("COLLECT_TIMEOUT", "30"))

_FLAKY_API_NAMES = {"flaky-api", "flaky_api"}

# ── Query metadata catalogue ──────────────────────────────────────────────────
# Describes each metric key so we can reconstruct PromQLRef objects later
# without re-rendering the templates.

_QUERY_META: dict[str, dict[str, Any]] = {
    "cpu": {
        "label":        "Container CPU usage rate",
        "query_type":   "range",
        "window_minutes": 15,
    },
    "memory": {
        "label":        "Container memory working set",
        "query_type":   "range",
        "window_minutes": 15,
    },
    "restarts": {
        "label":        "Container restart count trend",
        "query_type":   "range",
        "window_minutes": 60,
    },
    "flaky_error_rate": {
        "label":        "flaky-api HTTP 5xx error rate",
        "query_type":   "range",
        "window_minutes": 15,
    },
    "flaky_p95_latency": {
        "label":        "flaky-api p95 request latency",
        "query_type":   "range",
        "window_minutes": 15,
    },
    "flaky_request_rate": {
        "label":        "flaky-api total request rate",
        "query_type":   "range",
        "window_minutes": 15,
    },
    "flaky_injected_error_rate": {
        "label":        "flaky-api injected error rate (live gauge)",
        "query_type":   "instant",
        "window_minutes": None,
    },
    "flaky_injected_latency_ms": {
        "label":        "flaky-api injected latency ms (live gauge)",
        "query_type":   "instant",
        "window_minutes": None,
    },
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Single-query helpers ──────────────────────────────────────────────────────

async def _collect_range(
    name: str,
    template: str,
    minutes: int,
    errors: list[str],
    **kwargs: Any,
) -> dict[str, Any]:
    promql = pt.render(template, **kwargs)
    try:
        resp   = await pt.range_query(template, minutes=minutes, **kwargs)
        series = pt.extract_series(resp)
        if not series:
            return {"query": promql, "status": "no_data",
                    "summary": {"min": None, "max": None, "avg": None, "last": None},
                    "series": []}
        return {"query": promql, "status": "ok",
                "summary": pt.summarise(series), "series": series}
    except Exception as exc:
        msg = f"{name}: {exc}"
        log.warning("Evidence collection error — %s", msg)
        errors.append(msg)
        return {"query": promql, "status": "error", "error": str(exc), "series": []}


async def _collect_instant(
    name: str,
    template: str,
    errors: list[str],
    **kwargs: Any,
) -> dict[str, Any]:
    promql = pt.render(template, **kwargs) if kwargs else template
    try:
        resp   = await pt.instant(template, **kwargs) if kwargs else await pt.query_instant(template)
        scalar = pt.extract_scalar(resp)
        return {"query": promql,
                "status": "ok" if scalar is not None else "no_data",
                "value": scalar}
    except Exception as exc:
        msg = f"{name}: {exc}"
        log.warning("Evidence collection error — %s", msg)
        errors.append(msg)
        return {"query": promql, "status": "error", "error": str(exc)}


# ── PromQL query list builder ─────────────────────────────────────────────────

def build_promql_list(metrics: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Build the promql_queries list from collected metric blocks.

    Each entry:
      {
        "metric_key":      str,
        "label":           str,
        "promql":          str,   ← the rendered query stored in each block
        "query_type":      str,
        "window_minutes":  int | None,
      }

    Stored in the evidence packet and surfaced in IncidentDetail.
    """
    queries = []
    for key, block in metrics.items():
        promql = block.get("query", "")
        if not promql:
            continue
        meta = _QUERY_META.get(key, {})
        queries.append({
            "metric_key":     key,
            "label":          meta.get("label", key),
            "promql":         promql,
            "query_type":     meta.get("query_type", "range"),
            "window_minutes": meta.get("window_minutes"),
        })
    return queries


# ── Main collection entry point ───────────────────────────────────────────────

async def collect(
    incident_id: int,
    alertname: str,
    container: str,
    service: str,
    labels: dict[str, str],
) -> str:
    """
    Collect evidence for a new incident. Returns path to written JSON, or "".
    """
    collected_at = _now_iso()
    errors: list[str] = []
    metrics: dict[str, Any] = {}

    short_win   = 15
    restart_win = 60

    log.info("Collecting evidence for incident #%d  container=%s  service=%s",
             incident_id, container, service)

    # ── Container metrics (cAdvisor) ──────────────────────────────────────────

    async def collect_container():
        if not container:
            errors.append("No container label — skipping container metrics")
            return
        cpu, mem, restarts = await asyncio.gather(
            _collect_range("cpu",      pt.TEMPLATES["cpu_rate"],
                           short_win,   errors, container=container, window="2m"),
            _collect_range("memory",   pt.TEMPLATES["memory_working_set"],
                           short_win,   errors, container=container),
            _collect_range("restarts", pt.TEMPLATES["restart_count"],
                           restart_win, errors, container=container, window="5m"),
        )
        metrics["cpu"]      = cpu
        metrics["memory"]   = mem
        metrics["restarts"] = restarts

    # ── flaky-api application metrics ─────────────────────────────────────────

    async def collect_flaky():
        relevant = (
            service in _FLAKY_API_NAMES
            or container in _FLAKY_API_NAMES
            or "flaky" in alertname.lower()
            or labels.get("job", "") == "flaky-api"
        )
        if not relevant:
            return

        log.info("Incident #%d — collecting flaky-api application metrics", incident_id)

        task_map = {
            "flaky_error_rate":          _collect_range(
                "flaky_error_rate", pt.TEMPLATES["flaky_error_rate"],
                short_win, errors, window="2m"),
            "flaky_p95_latency":         _collect_range(
                "flaky_p95_latency", pt.TEMPLATES["flaky_p95_latency"],
                short_win, errors, window="5m"),
            "flaky_request_rate":        _collect_range(
                "flaky_request_rate", pt.TEMPLATES["flaky_request_rate"],
                short_win, errors, window="2m"),
            "flaky_injected_error_rate": _collect_instant(
                "flaky_injected_error_rate",
                pt.TEMPLATES["flaky_injected_error_rate"], errors),
            "flaky_injected_latency_ms": _collect_instant(
                "flaky_injected_latency_ms",
                pt.TEMPLATES["flaky_injected_latency_ms"], errors),
        }
        results = await asyncio.gather(*task_map.values())
        for key, result in zip(task_map.keys(), results):
            metrics[key] = result

    # ── Run with shared timeout ───────────────────────────────────────────────

    try:
        await asyncio.wait_for(
            asyncio.gather(collect_container(), collect_flaky()),
            timeout=COLLECT_TIMEOUT,
        )
    except asyncio.TimeoutError:
        msg = f"Evidence collection timed out after {COLLECT_TIMEOUT}s"
        log.warning(msg)
        errors.append(msg)

    # ── Build PromQL query list ───────────────────────────────────────────────

    promql_queries = build_promql_list(metrics)

    # ── Assemble packet ───────────────────────────────────────────────────────

    packet: dict[str, Any] = {
        "schema_version": "1",
        "incident_id":    incident_id,
        "collected_at":   collected_at,
        "container":      container,
        "service":        service,
        "alertname":      alertname,
        "labels":         labels,
        "windows": {
            "short_min":   short_win,
            "restart_min": restart_win,
        },
        "metrics":        metrics,
        "promql_queries": promql_queries,   # ← new: consumed by grafana_links
        "errors":         errors,
    }

    path = _write_packet(incident_id, packet)

    # ── Timeline entries ──────────────────────────────────────────────────────

    collected_ok  = [k for k in metrics if metrics[k].get("status") == "ok"]
    collected_err = [k for k in metrics if metrics[k].get("status") == "error"]

    await db.add_timeline_entry(
        incident_id,
        event="evidence_collected",
        detail=(
            f"Evidence collected → {path}  |  "
            f"metrics_ok={collected_ok}  |  metrics_error={collected_err}"
            + (f"  |  errors={errors}" if errors else "")
        ),
    )

    # Human-readable stats digest
    stats_lines = []
    if "cpu" in metrics and metrics["cpu"].get("status") == "ok":
        s = metrics["cpu"]["summary"]
        stats_lines.append(f"CPU last-15m:  avg={_fmt(s['avg'])} cores  max={_fmt(s['max'])} cores")
    if "memory" in metrics and metrics["memory"].get("status") == "ok":
        s = metrics["memory"]["summary"]
        stats_lines.append(f"Memory last-15m: avg={_fmt_mb(s['avg'])} MiB  max={_fmt_mb(s['max'])} MiB")
    if "restarts" in metrics and metrics["restarts"].get("status") == "ok":
        s = metrics["restarts"]["summary"]
        stats_lines.append(f"Restarts last-1h: total≈{_fmt(s['last'])} (increase)")
    if "flaky_error_rate" in metrics and metrics["flaky_error_rate"].get("status") == "ok":
        s = metrics["flaky_error_rate"]["summary"]
        stats_lines.append(f"flaky-api error rate last-15m: avg={_pct(s['avg'])}  max={_pct(s['max'])}")
    if "flaky_p95_latency" in metrics and metrics["flaky_p95_latency"].get("status") == "ok":
        s = metrics["flaky_p95_latency"]["summary"]
        stats_lines.append(f"flaky-api p95 latency last-15m: avg={_ms(s['avg'])} ms  max={_ms(s['max'])} ms")
    if "flaky_injected_error_rate" in metrics:
        v = metrics["flaky_injected_error_rate"].get("value")
        if v is not None:
            stats_lines.append(f"Injected error rate (live): {_pct(v)}")
    if "flaky_injected_latency_ms" in metrics:
        v = metrics["flaky_injected_latency_ms"].get("value")
        if v is not None:
            stats_lines.append(f"Injected latency (live): {v:.0f} ms")

    if stats_lines:
        await db.add_timeline_entry(
            incident_id,
            event="evidence_summary",
            detail="\n".join(stats_lines),
        )

    # Emit a timeline entry listing all PromQL queries for quick reference
    if promql_queries:
        query_lines = [
            f"  [{q['metric_key']}]  {q['label']}\n    {q['promql']}"
            for q in promql_queries
        ]
        await db.add_timeline_entry(
            incident_id,
            event="promql_queries_recorded",
            detail="PromQL queries used for evidence collection:\n" + "\n".join(query_lines),
        )

    log.info("Evidence packet written for incident #%d → %s  (%d metrics, %d queries, %d errors)",
             incident_id, path, len(metrics), len(promql_queries), len(errors))
    return path


# ── File I/O ──────────────────────────────────────────────────────────────────

def _write_packet(incident_id: int, packet: dict[str, Any]) -> str:
    Path(EVIDENCE_DIR).mkdir(parents=True, exist_ok=True)
    path = os.path.join(EVIDENCE_DIR, f"incident_{incident_id}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(packet, fh, indent=2, default=str)
    return path


def load_packet(incident_id: int) -> dict[str, Any] | None:
    path = os.path.join(EVIDENCE_DIR, f"incident_{incident_id}.json")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


# ── Formatting helpers ────────────────────────────────────────────────────────

def _fmt(v: float | None, decimals: int = 3) -> str:
    return f"{v:.{decimals}f}" if v is not None else "n/a"

def _fmt_mb(v: float | None) -> str:
    return f"{v / 1_048_576:.1f}" if v is not None else "n/a"

def _pct(v: float | None) -> str:
    return f"{v * 100:.1f}%" if v is not None else "n/a"

def _ms(v: float | None) -> str:
    return f"{v * 1000:.0f}" if v is not None else "n/a"
