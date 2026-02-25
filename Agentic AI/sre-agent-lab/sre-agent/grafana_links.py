"""
grafana_links.py — Grafana dashboard and Explore deep-link builder.

Generates two categories of links per incident:

1. Explore links  — one per PromQL query used during evidence collection.
   Opens Grafana Explore with the query pre-filled and time range anchored
   around the incident window (from  created_at - lookback  to  now).

2. Dashboard links — named links to fixed dashboards in the lab that are
   always useful regardless of which alert fired (e.g. the cAdvisor
   container overview).  These are link templates whose variable placeholders
   are substituted with container / service label values.

Configuration (env vars)
─────────────────────────
GRAFANA_URL          Grafana base URL reachable from the browser
                     default: http://localhost:3000

GRAFANA_DATASOURCE   Prometheus datasource UID (must match datasource.yml)
                     default: prometheus

GRAFANA_ORG_ID       Grafana org ID (1 for single-org installs)
                     default: 1

All link-building is pure string/URL manipulation — no HTTP calls are made
to Grafana.  The links are always generated even if Grafana is unreachable.
"""

from __future__ import annotations

import json
import os
import urllib.parse
from datetime import datetime, timedelta, timezone
from typing import Any


# ── Configuration ─────────────────────────────────────────────────────────────

GRAFANA_URL        = os.environ.get("GRAFANA_URL",        "http://localhost:3000")
GRAFANA_DATASOURCE = os.environ.get("GRAFANA_DATASOURCE", "prometheus")
GRAFANA_ORG_ID     = int(os.environ.get("GRAFANA_ORG_ID", "1"))

# How far before incident creation the Explore time window starts
_DEFAULT_LOOKBACK_MIN = 30
# How far after incident creation the Explore time window ends
_DEFAULT_LOOKAHEAD_MIN = 15


# ── Explore link builder ──────────────────────────────────────────────────────

def explore_link(
    promql: str,
    from_dt: datetime,
    to_dt: datetime,
    label: str = "",
) -> dict[str, str]:
    """
    Build a Grafana Explore deep-link for a single PromQL expression.

    Returns:
        {
            "label":   human-readable description,
            "url":     full Grafana Explore URL,
            "promql":  the raw PromQL expression,
        }

    The Explore URL encodes the datasource, time range, and query in the
    `left` query parameter as a JSON blob (Grafana's standard format).
    """
    # Grafana epoch-ms timestamps
    from_ms = int(from_dt.timestamp() * 1000)
    to_ms   = int(to_dt.timestamp()   * 1000)

    # Grafana Explore state object
    state = {
        "datasource": GRAFANA_DATASOURCE,
        "queries": [
            {
                "refId":      "A",
                "datasource": {"type": "prometheus", "uid": GRAFANA_DATASOURCE},
                "expr":       promql,
                "instant":    False,
                "range":      True,
            }
        ],
        "range": {
            "from": str(from_ms),
            "to":   str(to_ms),
        },
    }

    params = {
        "orgId": GRAFANA_ORG_ID,
        "left":  json.dumps(state, separators=(",", ":")),
    }

    url = (
        GRAFANA_URL.rstrip("/")
        + "/explore?"
        + urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
    )

    return {
        "label":  label or _auto_label(promql),
        "url":    url,
        "promql": promql,
    }


# ── Dashboard link builder ─────────────────────────────────────────────────────

# Named dashboard slugs / UIDs known to exist in this lab.
# Add more as dashboards are provisioned into grafana/provisioning/dashboards/.
_DASHBOARD_LINKS: list[dict[str, str]] = [
    {
        "label": "cAdvisor — Container Overview",
        "path":  "/d/cadvisor-overview/cadvisor-container-overview",
    },
    {
        "label": "Prometheus — Self Metrics",
        "path":  "/d/prometheus-self/prometheus-self-metrics",
    },
]

# Dashboard links that are only relevant for flaky-api incidents
_FLAKY_DASHBOARD_LINKS: list[dict[str, str]] = [
    {
        "label": "flaky-api — Request / Error / Latency",
        "path":  "/d/flaky-api/flaky-api-rel",
    },
]


def dashboard_links(
    container: str,
    service: str,
    from_dt: datetime,
    to_dt: datetime,
) -> list[dict[str, str]]:
    """
    Return a list of labelled Grafana dashboard deep-links relevant to
    this incident.  Time range and container/service variables are
    appended as query parameters so dashboards open in the right context.
    """
    from_ms = int(from_dt.timestamp() * 1000)
    to_ms   = int(to_dt.timestamp()   * 1000)

    base_params: dict[str, Any] = {
        "orgId": GRAFANA_ORG_ID,
        "from":  str(from_ms),
        "to":    str(to_ms),
    }
    if container:
        base_params["var-container"] = container
    if service:
        base_params["var-service"] = service

    qs = urllib.parse.urlencode(base_params)
    base = GRAFANA_URL.rstrip("/")

    links = []

    for dash in _DASHBOARD_LINKS:
        links.append({
            "label": dash["label"],
            "url":   f"{base}{dash['path']}?{qs}",
        })

    # Add flaky-api dashboards when relevant
    is_flaky = "flaky" in service.lower() or "flaky" in container.lower()
    if is_flaky:
        for dash in _FLAKY_DASHBOARD_LINKS:
            links.append({
                "label": dash["label"],
                "url":   f"{base}{dash['path']}?{qs}",
            })

    return links


# ── Main builder — called from main.py ───────────────────────────────────────

def build_links(
    incident_id: int,
    created_at: datetime,
    container: str,
    service: str,
    promql_queries: list[dict[str, str]],
    lookback_min: int = _DEFAULT_LOOKBACK_MIN,
    lookahead_min: int = _DEFAULT_LOOKAHEAD_MIN,
) -> dict[str, Any]:
    """
    Build the full set of Grafana links for an incident.

    Args:
        incident_id:    used for logging only
        created_at:     incident creation timestamp — anchors the time window
        container:      container_name label from the alert
        service:        service label from the alert
        promql_queries: list of {"label": str, "promql": str} dicts — one per
                        metric collected by EvidenceCollector
        lookback_min:   minutes before created_at to start the time window
        lookahead_min:  minutes after created_at to end the time window

    Returns:
        {
            "time_window": {"from": <iso>, "to": <iso>},
            "explore":     [{"label": str, "url": str, "promql": str}, ...],
            "dashboards":  [{"label": str, "url": str}, ...],
        }
    """
    # Ensure created_at is timezone-aware
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)

    from_dt = created_at - timedelta(minutes=lookback_min)
    to_dt   = created_at + timedelta(minutes=lookahead_min)

    explore = [
        explore_link(
            promql=q["promql"],
            from_dt=from_dt,
            to_dt=to_dt,
            label=q.get("label", ""),
        )
        for q in promql_queries
        if q.get("promql", "").strip()
    ]

    dashboards = dashboard_links(
        container=container,
        service=service,
        from_dt=from_dt,
        to_dt=to_dt,
    )

    return {
        "time_window": {
            "from": from_dt.isoformat(),
            "to":   to_dt.isoformat(),
        },
        "explore":    explore,
        "dashboards": dashboards,
    }


# ── Label heuristic ────────────────────────────────────────────────────────────

def _auto_label(promql: str) -> str:
    """
    Derive a short human label from a PromQL expression for display purposes.
    Extracts the leading metric name (up to first { or ().
    """
    clean = promql.strip()
    # Strip wrapping functions like rate(...), histogram_quantile(0.95, ...)
    for fn in ("histogram_quantile", "rate", "increase", "avg_over_time"):
        if clean.startswith(fn):
            # Extract inner metric name
            inner = clean[len(fn):].lstrip("(0123456789., ")
            clean = inner
            break
    # Take up to first label selector or paren
    for ch in ("{", "(", "["):
        idx = clean.find(ch)
        if idx > 0:
            clean = clean[:idx]
    return clean.strip() or promql[:60]
