"""
models.py — Pydantic v2 schemas for sre-agent.

Layers:
  1. Alertmanager webhook payload  (what we receive on POST /alert)
  2. DB row representations        (what we read from SQLite)
  3. API response models           (what we return to callers)
  4. Evidence packet               (structure of the collected metric snapshot)
  5. Grafana links                 (deep-links generated per incident)
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


# ── 1. Alertmanager webhook payload ──────────────────────────────────────────

class AlertmanagerAlert(BaseModel):
    """A single alert inside an Alertmanager group notification."""

    status: str
    labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)
    startsAt: datetime | None = None
    endsAt: datetime | None = None
    generatorURL: str = ""
    fingerprint: str = ""

    model_config = {"extra": "allow"}


class AlertmanagerWebhook(BaseModel):
    """Top-level body Alertmanager sends to a webhook receiver."""

    version: str = ""
    groupKey: str = ""
    truncatedAlerts: int = 0
    status: str
    receiver: str = ""
    groupLabels: dict[str, str] = Field(default_factory=dict)
    commonLabels: dict[str, str] = Field(default_factory=dict)
    commonAnnotations: dict[str, str] = Field(default_factory=dict)
    externalURL: str = ""
    alerts: list[AlertmanagerAlert] = Field(default_factory=list)

    model_config = {"extra": "allow"}


# ── 2. Timeline entry ─────────────────────────────────────────────────────────

class TimelineEntry(BaseModel):
    id: int
    incident_id: int
    created_at: datetime
    event: str
    detail: str = ""


# ── 3. Grafana link models ────────────────────────────────────────────────────

class ExploreLink(BaseModel):
    """A Grafana Explore deep-link pre-loaded with a single PromQL query."""

    label: str                  # human-readable description, e.g. "CPU usage"
    url: str                    # full Grafana Explore URL
    promql: str                 # the raw PromQL expression


class DashboardLink(BaseModel):
    """A link to a named Grafana dashboard with time range and variable params."""

    label: str
    url: str


class GrafanaTimeWindow(BaseModel):
    """The time window the Grafana links are anchored to."""

    from_: datetime = Field(alias="from")
    to: datetime

    model_config = {"populate_by_name": True}


class GrafanaLinks(BaseModel):
    """
    All Grafana deep-links generated for an incident.
    Returned as part of IncidentDetail.
    """

    time_window: dict[str, str]     # {"from": iso, "to": iso}
    explore: list[ExploreLink] = Field(default_factory=list)
    dashboards: list[DashboardLink] = Field(default_factory=list)


# ── 4. PromQL reference ───────────────────────────────────────────────────────

class PromQLRef(BaseModel):
    """
    A single PromQL query used during evidence collection.
    Surfaced in IncidentDetail so callers can replay or adapt the queries.
    """

    metric_key: str             # e.g. "cpu", "flaky_error_rate"
    label: str                  # human-readable description
    promql: str                 # rendered PromQL (variables already substituted)
    query_type: str = "range"   # "range" | "instant"
    window_minutes: int | None = None   # look-back window used for range queries


# ── 5a. LLM analysis models ──────────────────────────────────────────────────

class LLMHypothesis(BaseModel):
    cause: str
    confidence: float = Field(ge=0, le=1)
    evidence_refs: list[str] = Field(default_factory=list)


class LLMRecommendedAction(BaseModel):
    action: str
    risk: str
    why: str
    verify_signals: list[str] = Field(default_factory=list)


class LLMVerificationPlan(BaseModel):
    queries_to_check: list[str] = Field(default_factory=list)
    expected_improvement: list[str] = Field(default_factory=list)


class LLMAnalysis(BaseModel):
    provider: str
    model: str
    generated_at: datetime
    summary: str
    hypotheses: list[LLMHypothesis] = Field(default_factory=list)
    recommended_actions: list[LLMRecommendedAction] = Field(default_factory=list)
    verification_plan: LLMVerificationPlan


# ── 6. Incident response models ───────────────────────────────────────────────

class IncidentSummary(BaseModel):
    """Lightweight view returned by GET /incidents."""

    id: int
    created_at: datetime
    updated_at: datetime
    status: str
    alertname: str
    severity: str
    service: str
    container_name: str
    summary: str
    evidence_path: str = ""
    github_issue_url: str = ""


class IncidentDetail(IncidentSummary):
    """
    Full view returned by GET /incidents/{id}.

    Extends IncidentSummary with:
      - labels / annotations from the original alert
      - full timeline of events
      - evidence packet loaded from disk (raw metrics + summaries)
      - grafana_links: deep-links into Grafana Explore + dashboards
      - promql_queries: list of every PromQL query run during evidence collection
    """

    labels: dict[str, Any]
    annotations: dict[str, Any]
    raw_alert_hash: str
    timeline: list[TimelineEntry] = Field(default_factory=list)
    evidence: dict[str, Any] | None = None
    grafana_links: GrafanaLinks | None = None
    promql_queries: list[PromQLRef] = Field(default_factory=list)
    llm_analysis: LLMAnalysis | None = None


# ── 7. Evidence packet model ──────────────────────────────────────────────────

class MetricBlock(BaseModel):
    query: str
    status: str
    summary: dict[str, float | None] | None = None
    series: list[Any] = Field(default_factory=list)
    value: float | None = None
    error: str | None = None


class EvidencePacket(BaseModel):
    schema_version: str = "1"
    incident_id: int
    collected_at: datetime
    container: str
    service: str
    alertname: str
    labels: dict[str, str] = Field(default_factory=dict)
    windows: dict[str, int] = Field(default_factory=dict)
    metrics: dict[str, Any] = Field(default_factory=dict)
    promql_queries: list[dict[str, Any]] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


# ── 8. Generic responses ──────────────────────────────────────────────────────

class AlertReceiveResponse(BaseModel):
    received: int
    incidents_created: int
    incidents_updated: int


class HealthResponse(BaseModel):
    status: str
    db: str
    incidents_total: int
    prometheus_url: str = ""
    grafana_url: str = ""
    evidence_dir: str = ""
    smtp_host: str = ""
    smtp_port: int = 25
    email_enabled: bool = True
