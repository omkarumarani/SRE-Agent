"""
llm_provider.py — Pluggable LLM provider interface for incident analysis.

Supports:
  - OpenAI Chat Completions API
  - Anthropic Claude Messages API

Provider is selected via env var:
  LLM_PROVIDER=openai | claude | none

Credentials and model env vars:
  OPENAI_API_KEY, OPENAI_MODEL, OPENAI_BASE_URL
  ANTHROPIC_API_KEY, ANTHROPIC_MODEL, ANTHROPIC_BASE_URL
"""

from __future__ import annotations

import abc
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

import httpx
from pydantic import BaseModel, Field

import sensitive_data_guard as sdg

log = logging.getLogger("sre_agent.llm")

LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "none").strip().lower()
LLM_TIMEOUT = float(os.environ.get("LLM_TIMEOUT", "25"))

_OPENAI_BASE_URL = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
_OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
_OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")

_ANTHROPIC_BASE_URL = os.environ.get("ANTHROPIC_BASE_URL", "https://api.anthropic.com/v1").rstrip("/")
_ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
_ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-3-5-sonnet-latest")


class IncidentLLMResponse(BaseModel):
    summary: str
    hypotheses: list[dict[str, Any]] = Field(default_factory=list)
    recommended_actions: list[dict[str, Any]] = Field(default_factory=list)
    verification_plan: dict[str, Any] = Field(default_factory=dict)


class LLMProvider(abc.ABC):
    @property
    @abc.abstractmethod
    def provider_name(self) -> str:
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def model_name(self) -> str:
        raise NotImplementedError

    @abc.abstractmethod
    async def complete_json(self, prompt: str) -> dict[str, Any]:
        raise NotImplementedError


class OpenAIProvider(LLMProvider):
    @property
    def provider_name(self) -> str:
        return "openai"

    @property
    def model_name(self) -> str:
        return _OPENAI_MODEL

    async def complete_json(self, prompt: str) -> dict[str, Any]:
        headers = {
            "Authorization": f"Bearer {_OPENAI_API_KEY}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": _OPENAI_MODEL,
            "temperature": 0.2,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are an SRE incident analyst. Output JSON only. "
                        "Do not add markdown or code fences."
                    ),
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
            "response_format": {"type": "json_object"},
        }
        async with httpx.AsyncClient(timeout=LLM_TIMEOUT) as client:
            r = await client.post(f"{_OPENAI_BASE_URL}/chat/completions", headers=headers, json=payload)
            r.raise_for_status()
            body = r.json()
            content = body["choices"][0]["message"]["content"]
            return _extract_json(content)


class ClaudeProvider(LLMProvider):
    @property
    def provider_name(self) -> str:
        return "claude"

    @property
    def model_name(self) -> str:
        return _ANTHROPIC_MODEL

    async def complete_json(self, prompt: str) -> dict[str, Any]:
        headers = {
            "x-api-key": _ANTHROPIC_API_KEY,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        payload = {
            "model": _ANTHROPIC_MODEL,
            "max_tokens": 1000,
            "temperature": 0.2,
            "system": "You are an SRE incident analyst. Output JSON only.",
            "messages": [
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
        }
        async with httpx.AsyncClient(timeout=LLM_TIMEOUT) as client:
            r = await client.post(f"{_ANTHROPIC_BASE_URL}/messages", headers=headers, json=payload)
            r.raise_for_status()
            body = r.json()
            chunks = body.get("content", [])
            text = "\n".join(c.get("text", "") for c in chunks if c.get("type") == "text")
            return _extract_json(text)


def get_provider() -> LLMProvider | None:
    if LLM_PROVIDER == "openai":
        if not _OPENAI_API_KEY:
            log.warning("LLM_PROVIDER=openai but OPENAI_API_KEY is missing; skipping LLM analysis")
            return None
        return OpenAIProvider()
    if LLM_PROVIDER == "claude":
        if not _ANTHROPIC_API_KEY:
            log.warning("LLM_PROVIDER=claude but ANTHROPIC_API_KEY is missing; skipping LLM analysis")
            return None
        return ClaudeProvider()
    return None


def build_sanitized_aggregated_evidence(
    incident_id: int,
    alertname: str,
    severity: str,
    service: str,
    container: str,
    summary: str,
    labels: dict[str, Any],
    evidence_packet: dict[str, Any] | None,
) -> dict[str, Any]:
    metrics = (evidence_packet or {}).get("metrics", {})

    agg_metrics: dict[str, Any] = {}
    for key, block in metrics.items():
        status = block.get("status", "unknown")
        item: dict[str, Any] = {"status": status}
        if isinstance(block.get("summary"), dict):
            item["summary"] = {
                "min": block["summary"].get("min"),
                "max": block["summary"].get("max"),
                "avg": block["summary"].get("avg"),
                "last": block["summary"].get("last"),
            }
        if "value" in block:
            item["value"] = block.get("value")
        if block.get("error"):
            item["error"] = block.get("error")
        agg_metrics[key] = item

    promql_refs = []
    for q in (evidence_packet or {}).get("promql_queries", []):
        promql_refs.append({
            "metric_key": q.get("metric_key", ""),
            "label": q.get("label", ""),
            "query_type": q.get("query_type", ""),
            "window_minutes": q.get("window_minutes"),
        })

    payload = {
        "incident": {
            "id": incident_id,
            "alertname": alertname,
            "severity": severity,
            "service": service,
            "container": container,
            "summary": summary,
            "labels": labels,
        },
        "aggregated_evidence": {
            "collected_at": (evidence_packet or {}).get("collected_at"),
            "windows": (evidence_packet or {}).get("windows", {}),
            "metrics": agg_metrics,
            "promql_refs": promql_refs,
            "errors": (evidence_packet or {}).get("errors", []),
        },
    }
    return _sanitize_obj(payload)


def _prompt_for_analysis(sanitized_payload: dict[str, Any]) -> str:
    schema = {
        "summary": "string with exactly 5 lines",
        "hypotheses": [
            {
                "cause": "string",
                "confidence": "number in [0,1]",
                "evidence_refs": ["string"],
            }
        ],
        "recommended_actions": [
            {
                "action": "string",
                "risk": "low|medium|high",
                "why": "string",
                "verify_signals": ["string"],
            }
        ],
        "verification_plan": {
            "queries_to_check": ["string"],
            "expected_improvement": ["string"],
        },
    }
    return (
        "Analyze this incident from sanitized aggregated evidence only.\n"
        "Do not infer secrets, credentials, or PII.\n"
        "Return strict JSON only matching this schema:\n"
        f"{json.dumps(schema, indent=2)}\n\n"
        "Incident payload:\n"
        f"{json.dumps(sanitized_payload, indent=2)}"
    )


async def generate_incident_analysis(
    incident_id: int,
    alertname: str,
    severity: str,
    service: str,
    container: str,
    summary: str,
    labels: dict[str, Any],
    evidence_packet: dict[str, Any] | None,
) -> dict[str, Any] | None:
    provider = get_provider()
    if not provider:
        return None

    sanitized = build_sanitized_aggregated_evidence(
        incident_id=incident_id,
        alertname=alertname,
        severity=severity,
        service=service,
        container=container,
        summary=summary,
        labels=labels,
        evidence_packet=evidence_packet,
    )

    prompt = _prompt_for_analysis(sanitized)
    raw = await provider.complete_json(prompt)

    parsed = IncidentLLMResponse.model_validate(raw)
    normalized_summary = _normalize_summary_5_lines(parsed.summary)

    return {
        "provider": provider.provider_name,
        "model": provider.model_name,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": normalized_summary,
        "hypotheses": parsed.hypotheses,
        "recommended_actions": parsed.recommended_actions,
        "verification_plan": parsed.verification_plan,
        "input": sanitized,
    }


def _normalize_summary_5_lines(text: str) -> str:
    lines = [ln.strip(" -\t") for ln in text.splitlines() if ln.strip()]
    if len(lines) >= 5:
        return "\n".join(lines[:5])
    while len(lines) < 5:
        lines.append("n/a")
    return "\n".join(lines)


def _extract_json(raw_text: str) -> dict[str, Any]:
    text = (raw_text or "").strip()
    if not text:
        raise ValueError("LLM returned empty response")

    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:].strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise
        return json.loads(text[start:end + 1])


def _sanitize_obj(value: Any) -> Any:
    if isinstance(value, str):
        return sdg.redact(value)
    if isinstance(value, list):
        return [_sanitize_obj(v) for v in value]
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            if isinstance(v, str):
                out[k] = sdg.redact_dict({str(k): v}).get(str(k), v)
            else:
                out[k] = _sanitize_obj(v)
        return out
    return value
