"""
prometheus_tool.py — async Prometheus HTTP API client for sre-agent.

PrometheusTool wraps the Prometheus HTTP API (/api/v1/query and
/api/v1/query_range) and provides:

  - query_instant(promql)           → single scalar/vector result
  - query_range(promql, start, end, step)  → time-series matrix
  - render(template, **vars)        → interpolate a PromQL template string
                                       then run it as an instant query

PromQL template variables use {var} Python format syntax, e.g.:
  "rate(container_cpu_usage_seconds_total{{name='{container}',image!=''}}[5m])"
  → render(template, container="flaky-api")

All methods return plain Python dicts/lists — no Pydantic parsing here so the
evidence collector can store raw JSON without impedance mismatch.
"""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

log = logging.getLogger("sre_agent.prometheus_tool")

PROMETHEUS_URL = os.environ.get("PROMETHEUS_URL", "http://prometheus:9090")
DEFAULT_TIMEOUT = float(os.environ.get("PROMETHEUS_TIMEOUT_SEC", "10"))

# ── Reusable async client (module-level, one per process) ─────────────────────

_client: httpx.AsyncClient | None = None


def get_client() -> httpx.AsyncClient:
    global _client
    if _client is None or _client.is_closed:
        _client = httpx.AsyncClient(
            base_url=PROMETHEUS_URL,
            timeout=DEFAULT_TIMEOUT,
        )
    return _client


async def close_client() -> None:
    global _client
    if _client and not _client.is_closed:
        await _client.aclose()
        _client = None


# ── Low-level API wrappers ────────────────────────────────────────────────────

async def query_instant(
    promql: str,
    at: datetime | None = None,
) -> dict[str, Any]:
    """
    POST /api/v1/query — instant vector/scalar query.

    Returns the raw Prometheus JSON response dict:
      { "status": "success", "data": { "resultType": ..., "result": [...] } }

    On HTTP or API error, returns:
      { "status": "error", "error": "<message>", "promql": promql }
    """
    params: dict[str, Any] = {"query": promql}
    if at is not None:
        params["time"] = at.timestamp()

    try:
        resp = await get_client().get("/api/v1/query", params=params)
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") != "success":
            log.warning("Prometheus query failed: %s  promql=%s", data.get("error"), promql)
            return {"status": "error", "error": data.get("error", "unknown"), "promql": promql}
        return data
    except httpx.HTTPStatusError as exc:
        log.error("Prometheus HTTP error %s for promql: %s", exc.response.status_code, promql)
        return {"status": "error", "error": str(exc), "promql": promql}
    except Exception as exc:
        log.error("Prometheus query exception: %s  promql=%s", exc, promql)
        return {"status": "error", "error": str(exc), "promql": promql}


async def query_range(
    promql: str,
    start: datetime,
    end: datetime,
    step: str = "30s",
) -> dict[str, Any]:
    """
    GET /api/v1/query_range — range query returning a matrix.

    step accepts Prometheus duration strings: "15s", "1m", "5m", etc.
    Returns the raw Prometheus JSON response dict.
    """
    params = {
        "query": promql,
        "start": start.timestamp(),
        "end":   end.timestamp(),
        "step":  step,
    }
    try:
        resp = await get_client().get("/api/v1/query_range", params=params)
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") != "success":
            log.warning("Prometheus range query failed: %s  promql=%s", data.get("error"), promql)
            return {"status": "error", "error": data.get("error", "unknown"), "promql": promql}
        return data
    except httpx.HTTPStatusError as exc:
        log.error("Prometheus HTTP %s for range promql: %s", exc.response.status_code, promql)
        return {"status": "error", "error": str(exc), "promql": promql}
    except Exception as exc:
        log.error("Prometheus range query exception: %s  promql=%s", exc, promql)
        return {"status": "error", "error": str(exc), "promql": promql}


# ── PromQL template helpers ───────────────────────────────────────────────────

def render(template: str, **kwargs: Any) -> str:
    """
    Interpolate a PromQL template string.

    PromQL uses { } for label matchers, which conflicts with Python str.format().
    Convention used here: label selectors inside PromQL are written with doubled
    braces {{ }}, and template variables use single braces { }.

    Example:
        tpl = "rate(container_cpu_usage_seconds_total{{name='{container}'}}[{window}])"
        render(tpl, container="flaky-api", window="5m")
        → "rate(container_cpu_usage_seconds_total{name='flaky-api'}[5m])"
    """
    return template.format(**kwargs)


async def instant(template: str, **kwargs: Any) -> dict[str, Any]:
    """Render a template then run as an instant query. Convenience wrapper."""
    return await query_instant(render(template, **kwargs))


async def range_query(
    template: str,
    minutes: int = 15,
    step: str = "30s",
    **kwargs: Any,
) -> dict[str, Any]:
    """
    Render a template then run a range query over the last `minutes` minutes.
    Convenience wrapper used by EvidenceCollector.
    """
    now   = datetime.now(timezone.utc)
    start = now - timedelta(minutes=minutes)
    return await query_range(render(template, **kwargs), start=start, end=now, step=step)


# ── Scalar extraction helpers ─────────────────────────────────────────────────

def extract_scalar(response: dict[str, Any]) -> float | None:
    """
    Pull the first numeric value from an instant query response.
    Returns None if the query errored or returned no data.
    """
    try:
        results = response["data"]["result"]
        if not results:
            return None
        # instant vector: each result is {"metric": {...}, "value": [ts, "val"]}
        val = results[0]["value"][1]
        return float(val)
    except (KeyError, IndexError, TypeError, ValueError):
        return None


def extract_series(response: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Extract time-series from a range query response as a list of
    {"metric": {...}, "values": [[ts, val], ...]} dicts.
    Returns [] on error.
    """
    try:
        return response["data"]["result"]
    except (KeyError, TypeError):
        return []


def series_to_floats(series: list[dict]) -> list[tuple[float, float]]:
    """
    Flatten the first series in a range result to [(timestamp, value), ...].
    Useful for min/max/avg summarisation.
    """
    if not series:
        return []
    return [(float(v[0]), float(v[1])) for v in series[0].get("values", [])]


def summarise(series: list[dict]) -> dict[str, float | None]:
    """
    Return {min, max, avg, last} for the first series in a range result.
    All None if the series is empty.
    """
    pts = series_to_floats(series)
    if not pts:
        return {"min": None, "max": None, "avg": None, "last": None}
    vals = [v for _, v in pts]
    return {
        "min":  min(vals),
        "max":  max(vals),
        "avg":  sum(vals) / len(vals),
        "last": vals[-1],
    }


# ── Pre-built PromQL templates ────────────────────────────────────────────────
# Used by EvidenceCollector. Double-brace {{ }} = literal PromQL label selector.
# Single-brace {var} = Python template variable.

TEMPLATES = {
    # Container-level (cAdvisor)
    "cpu_rate": (
        "rate(container_cpu_usage_seconds_total"
        "{{name='{container}',image!=''}}[{window}])"
    ),
    "memory_working_set": (
        "container_memory_working_set_bytes"
        "{{name='{container}',image!=''}}"
    ),
    "restart_count": (
        "increase(container_restart_count"
        "{{name='{container}',image!=''}}[{window}])"
    ),

    # flaky-api application metrics
    "flaky_error_rate": (
        "rate(flaky_api_requests_total{{job='flaky-api',status_code=~'5..'}}[{window}])"
        " / "
        "rate(flaky_api_requests_total{{job='flaky-api'}}[{window}])"
    ),
    "flaky_p95_latency": (
        "histogram_quantile(0.95, "
        "rate(flaky_api_request_duration_seconds_bucket{{job='flaky-api',endpoint='/work'}}[{window}]))"
    ),
    "flaky_request_rate": (
        "rate(flaky_api_requests_total{{job='flaky-api'}}[{window}])"
    ),
    "flaky_injected_error_rate": (
        "flaky_api_injected_error_rate"
    ),
    "flaky_injected_latency_ms": (
        "flaky_api_injected_latency_ms"
    ),
}
