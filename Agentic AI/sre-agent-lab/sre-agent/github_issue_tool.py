"""
github_issue_tool.py — optional GitHub issue creation for new incidents.

Enabled only when both env vars are set:
  - GITHUB_TOKEN
  - GITHUB_REPO   (owner/repo)
"""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

import sensitive_data_guard as sdg

log = logging.getLogger("sre_agent.github_issue")

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "").strip()
GITHUB_REPO = os.environ.get("GITHUB_REPO", "").strip()
GITHUB_API_BASE = os.environ.get("GITHUB_API_BASE", "https://api.github.com").rstrip("/")


def is_enabled() -> bool:
    return bool(GITHUB_TOKEN and GITHUB_REPO)


async def create_incident_issue(
    incident_id: int,
    alertname: str,
    container: str,
    summary: str,
    evidence_packet: dict[str, Any] | None,
    grafana_links: dict[str, Any] | None,
    llm_analysis: dict[str, Any] | None,
) -> str | None:
    """Create issue and return URL, or None when disabled/failed."""
    if not is_enabled():
        return None

    title = _build_title(alertname, container)
    body = _build_body(
        incident_id=incident_id,
        summary=summary,
        evidence_packet=evidence_packet,
        grafana_links=grafana_links,
        llm_analysis=llm_analysis,
    )

    payload = {"title": title, "body": body}
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.post(
                f"{GITHUB_API_BASE}/repos/{GITHUB_REPO}/issues",
                headers=headers,
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("html_url")
    except Exception as exc:
        log.warning("GitHub issue creation failed for incident #%d: %s", incident_id, exc)
        return None


def _build_title(alertname: str, container: str) -> str:
    clean_alertname = sdg.redact(alertname or "unknown")
    clean_container = sdg.redact(container or "unknown")
    return f"[SRE-LAB] {clean_alertname} {clean_container}".strip()


def _build_body(
    incident_id: int,
    summary: str,
    evidence_packet: dict[str, Any] | None,
    grafana_links: dict[str, Any] | None,
    llm_analysis: dict[str, Any] | None,
) -> str:
    lines: list[str] = []

    lines.append(f"## Incident #{incident_id}")
    lines.append("")
    lines.append("### Summary")
    lines.append(sdg.redact(summary or "n/a"))
    lines.append("")

    lines.append("### Evidence Summary")
    lines.extend(_evidence_summary_lines(evidence_packet))
    lines.append("")

    lines.append("### PromQL Queries")
    lines.extend(_promql_lines(evidence_packet))
    lines.append("")

    lines.append("### Grafana Link")
    grafana_url = _first_grafana_url(grafana_links)
    lines.append(grafana_url or "n/a")
    lines.append("")

    lines.append("### LLM Summary")
    llm_summary = ((llm_analysis or {}).get("summary") or "n/a")
    lines.append(sdg.redact(llm_summary))

    return "\n".join(lines)


def _evidence_summary_lines(evidence_packet: dict[str, Any] | None) -> list[str]:
    if not evidence_packet:
        return ["- Evidence not yet collected."]

    metrics = evidence_packet.get("metrics", {})
    out: list[str] = []
    for key, block in metrics.items():
        status = block.get("status", "unknown")
        summary = block.get("summary") or {}
        avg = summary.get("avg")
        maxv = summary.get("max")
        last = summary.get("last")
        if isinstance(summary, dict):
            out.append(f"- {key}: status={status}, avg={avg}, max={maxv}, last={last}")
        elif "value" in block:
            out.append(f"- {key}: status={status}, value={block.get('value')}")
        else:
            out.append(f"- {key}: status={status}")

    errors = evidence_packet.get("errors", [])
    if errors:
        out.append("- errors:")
        for err in errors:
            out.append(f"  - {sdg.redact(str(err))}")

    return out or ["- No metric data available."]


def _promql_lines(evidence_packet: dict[str, Any] | None) -> list[str]:
    if not evidence_packet:
        return ["- n/a"]
    refs = evidence_packet.get("promql_queries", [])
    if not refs:
        return ["- n/a"]
    return [f"- {sdg.redact(q.get('promql', ''))}" for q in refs]


def _first_grafana_url(grafana_links: dict[str, Any] | None) -> str:
    if not grafana_links:
        return ""
    explore = grafana_links.get("explore", [])
    dashboards = grafana_links.get("dashboards", [])
    if explore:
        return sdg.redact(str(explore[0].get("url", "")))
    if dashboards:
        return sdg.redact(str(dashboards[0].get("url", "")))
    return ""
