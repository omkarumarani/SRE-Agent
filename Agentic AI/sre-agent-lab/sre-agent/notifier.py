"""
notifier.py — async email notifier for sre-agent.

Sends a plain-text + HTML multipart email whenever a new incident is opened.
Uses smtp4dev (or any unauthenticated SMTP relay) via aiosmtplib.

Email contents
──────────────
  Subject : [sre-agent] <SEVERITY> #<id> — <alertname> on <container>
  Body    : incident summary · alert labels · evidence stats · grafana links

Configuration (env vars)
─────────────────────────
  SMTP_HOST        default: smtp4dev
  SMTP_PORT        default: 25
  EMAIL_FROM       default: sre-agent@lab.local
  EMAIL_TO         default: oncall@lab.local   (comma-separated for multiple)
  EMAIL_ENABLED    set "false" to suppress all emails   default: true
    SLACK_WEBHOOK_URL optional incoming webhook URL
    TELEGRAM_BOT_TOKEN optional bot token for Telegram API
    TELEGRAM_CHAT_ID   optional target chat id for Telegram API

Errors are always caught and logged — a failed send never aborts
incident processing.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

import aiosmtplib
import httpx

import sensitive_data_guard as sdg

log = logging.getLogger("sre_agent.notifier")

# ── Configuration ─────────────────────────────────────────────────────────────

SMTP_HOST     = os.environ.get("SMTP_HOST",     "smtp4dev")
SMTP_PORT     = int(os.environ.get("SMTP_PORT", "25"))
EMAIL_FROM    = os.environ.get("EMAIL_FROM",    "sre-agent@lab.local")
EMAIL_TO_RAW  = os.environ.get("EMAIL_TO",      "oncall@lab.local")
EMAIL_ENABLED = os.environ.get("EMAIL_ENABLED", "true").lower() not in ("false", "0", "no")
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "").strip()
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "").strip()

EMAIL_TO: list[str] = [a.strip() for a in EMAIL_TO_RAW.split(",") if a.strip()]


# ── Public API ────────────────────────────────────────────────────────────────

async def notify_incident_opened(
    incident_id: int,
    alertname: str,
    severity: str,
    service: str,
    container_name: str,
    summary: str,
    created_at: str | datetime,
    labels: dict[str, str],
    evidence_packet: dict[str, Any] | None,
    grafana_links: dict[str, Any] | None,
) -> None:
    """
    Fire a new-incident email.  All args are plain Python types — no Pydantic
    dependency — so this can be called from main.py before or after evidence
    collection completes.  All errors are swallowed.
    """
    clean_alertname = sdg.redact(alertname or "")
    clean_severity = sdg.redact(severity or "")
    clean_service = sdg.redact(service or "")
    clean_container = sdg.redact(container_name or "")
    clean_summary = sdg.redact(summary or "")
    clean_labels = sdg.redact_dict(labels or {})
    clean_evidence = _sanitize_obj(evidence_packet)
    clean_grafana = _sanitize_obj(grafana_links)

    subject   = _subject(incident_id, clean_severity, clean_alertname, clean_container)
    text_body = _text(
        incident_id,
        clean_alertname,
        clean_severity,
        clean_service,
        clean_container,
        clean_summary,
        created_at,
        clean_labels,
        clean_evidence,
        clean_grafana,
    )
    html_body = _html(
        incident_id,
        clean_alertname,
        clean_severity,
        clean_service,
        clean_container,
        clean_summary,
        created_at,
        clean_labels,
        clean_evidence,
        clean_grafana,
    )

    if EMAIL_ENABLED and EMAIL_TO:
        try:
            await _send_email(subject, text_body, html_body)
            log.info("Incident #%d email sent → %s", incident_id, EMAIL_TO)
        except Exception as exc:
            log.error("Email send failed for incident #%d: %s", incident_id, exc)
    elif not EMAIL_ENABLED:
        log.debug("Email disabled — skipping incident #%d", incident_id)
    else:
        log.warning("EMAIL_TO is empty — skipping incident #%d email", incident_id)

    if SLACK_WEBHOOK_URL:
        try:
            await _send_slack(subject, text_body)
            log.info("Incident #%d Slack notification sent", incident_id)
        except Exception as exc:
            log.error("Slack send failed for incident #%d: %s", incident_id, exc)
    else:
        log.debug("SLACK_WEBHOOK_URL not set — skipping Slack for incident #%d", incident_id)

    if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
        try:
            await _send_telegram(subject, text_body)
            log.info("Incident #%d Telegram notification sent", incident_id)
        except Exception as exc:
            log.error("Telegram send failed for incident #%d: %s", incident_id, exc)
    else:
        log.debug(
            "TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID missing — skipping Telegram for incident #%d",
            incident_id,
        )


# ── SMTP ──────────────────────────────────────────────────────────────────────

async def _send_email(subject: str, text_body: str, html_body: str) -> None:
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = EMAIL_FROM
    msg["To"]      = ", ".join(EMAIL_TO)
    msg.attach(MIMEText(text_body, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html",  "utf-8"))

    await aiosmtplib.send(
        msg,
        hostname=SMTP_HOST,
        port=SMTP_PORT,
        use_tls=False,
        start_tls=False,
    )


async def _send_slack(subject: str, text_body: str) -> None:
    payload = {
        "text": f"{subject}\n\n{text_body}",
    }
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(SLACK_WEBHOOK_URL, json=payload)
        resp.raise_for_status()


async def _send_telegram(subject: str, text_body: str) -> None:
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": f"{subject}\n\n{text_body}",
        "disable_web_page_preview": True,
    }
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(url, json=payload)
        resp.raise_for_status()


# ── Subject ───────────────────────────────────────────────────────────────────

def _subject(incident_id: int, severity: str, alertname: str, container: str) -> str:
    tag    = (severity or "UNKNOWN").upper()
    target = container or alertname
    return f"[sre-agent] {tag} #{incident_id} — {alertname} on {target}"


# ── Plain-text body ───────────────────────────────────────────────────────────

def _text(
    incident_id: int,
    alertname: str,
    severity: str,
    service: str,
    container_name: str,
    summary: str,
    created_at: str | datetime,
    labels: dict[str, str],
    evidence_packet: dict[str, Any] | None,
    grafana_links: dict[str, Any] | None,
) -> str:
    L: list[str] = []

    L += [
        "=" * 62,
        f"INCIDENT #{incident_id} — {alertname}",
        "=" * 62,
        "",
        f"Summary   : {summary}",
        f"Severity  : {severity or 'n/a'}",
        f"Service   : {service or 'n/a'}",
        f"Container : {container_name or 'n/a'}",
        f"Opened    : {_fmt_dt(created_at)}",
        f"Status    : open",
        "",
    ]

    if labels:
        L += ["ALERT LABELS", "-" * 40]
        for k, v in sorted(labels.items()):
            L.append(f"  {k:<32} {v}")
        L.append("")

    ev = _ev_text(evidence_packet)
    if ev:
        L += ["EVIDENCE SUMMARY  (last 15 min)", "-" * 40]
        L += ev
        L.append("")

    gl = _gl_text(grafana_links)
    if gl:
        L += ["GRAFANA LINKS", "-" * 40]
        L += gl
        L.append("")

    L += [
        "─" * 62,
        "Generated by sre-agent.",
        f"Incident detail : http://localhost:8081/incidents/{incident_id}",
        "All incidents   : http://localhost:8081/incidents",
    ]
    return "\n".join(L)


# ── HTML body ─────────────────────────────────────────────────────────────────

_SEV_COLOUR = {"critical": "#c0392b", "warning": "#e67e22", "info": "#2980b9"}
_DEFAULT_COLOUR = "#7f8c8d"


def _html(
    incident_id: int,
    alertname: str,
    severity: str,
    service: str,
    container_name: str,
    summary: str,
    created_at: str | datetime,
    labels: dict[str, str],
    evidence_packet: dict[str, Any] | None,
    grafana_links: dict[str, Any] | None,
) -> str:
    accent = _SEV_COLOUR.get((severity or "").lower(), _DEFAULT_COLOUR)
    sev_tag = (severity or "UNKNOWN").upper()

    out: list[str] = [f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8">
<style>
  body      {{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
              background:#f4f6f8;margin:0;padding:20px;color:#2c3e50}}
  .card     {{background:#fff;border-radius:6px;max-width:680px;margin:0 auto;
              box-shadow:0 2px 8px rgba(0,0,0,.08);overflow:hidden}}
  .hdr      {{background:{accent};color:#fff;padding:20px 24px}}
  .hdr h1   {{margin:0;font-size:20px}}
  .hdr p    {{margin:6px 0 0;font-size:13px;opacity:.85}}
  .badge    {{display:inline-block;background:rgba(255,255,255,.25);border-radius:3px;
              padding:2px 8px;font-size:12px;font-weight:600;letter-spacing:.5px;
              margin-bottom:6px}}
  .body     {{padding:20px 24px}}
  h2        {{font-size:13px;text-transform:uppercase;letter-spacing:.5px;
              color:{accent};margin:20px 0 8px;border-bottom:2px solid {accent};
              padding-bottom:4px}}
  table     {{width:100%;border-collapse:collapse;font-size:13px}}
  td        {{padding:5px 8px;border-bottom:1px solid #ecf0f1;vertical-align:top}}
  td:first-child{{width:36%;color:#7f8c8d;font-weight:500;white-space:nowrap}}
  .metric   {{background:#f8f9fa;border-radius:4px;padding:7px 12px;
              margin:3px 0;font-size:13px}}
  .ebtn     {{display:inline-block;background:{accent};color:#fff!important;
              text-decoration:none;padding:5px 12px;border-radius:4px;
              font-size:12px;font-weight:600;margin:3px 3px 3px 0}}
  .dlink    {{color:{accent}!important;font-size:13px;text-decoration:none;
              display:block;margin:3px 0}}
  .footer   {{background:#f4f6f8;padding:12px 24px;font-size:11px;
              color:#95a5a6;text-align:center}}
  a         {{color:{accent}}}
  code      {{background:#eef;padding:1px 4px;border-radius:3px;font-size:12px}}
</style>
</head>
<body>
<div class="card">
  <div class="hdr">
    <div class="badge">{sev_tag}</div>
    <h1>Incident #{incident_id} &mdash; {_he(alertname)}</h1>
    <p>{_he(summary)}</p>
  </div>
  <div class="body">
    <h2>Incident Details</h2>
    <table>
      <tr><td>Severity</td>  <td>{_he(severity  or 'n/a')}</td></tr>
      <tr><td>Service</td>   <td>{_he(service   or 'n/a')}</td></tr>
      <tr><td>Container</td> <td>{_he(container_name or 'n/a')}</td></tr>
      <tr><td>Opened</td>    <td>{_he(_fmt_dt(created_at))}</td></tr>
      <tr><td>Status</td>    <td>open</td></tr>
    </table>"""]

    # Labels
    if labels:
        out.append("    <h2>Alert Labels</h2>\n    <table>")
        for k, v in sorted(labels.items()):
            out.append(f"      <tr><td>{_he(k)}</td><td>{_he(v)}</td></tr>")
        out.append("    </table>")

    # Evidence
    ev_blocks = _ev_html(evidence_packet)
    if ev_blocks:
        out.append(
            "    <h2>Evidence Summary "
            "<small style='font-size:11px;color:#95a5a6;text-transform:none'>"
            "(last 15 min)</small></h2>"
        )
        for b in ev_blocks:
            out.append(f'    <div class="metric">{b}</div>')

    # Grafana links
    explore, dashboards = _gl_html(grafana_links)
    if explore or dashboards:
        out.append("    <h2>Grafana Links</h2>")
        if explore:
            out.append(
                "    <p style='font-size:12px;color:#7f8c8d;margin:0 0 6px'>"
                "Explore queries (time-windowed to incident):</p>"
            )
            for label, url in explore:
                out.append(f'    <a href="{_he(url)}" class="ebtn">{_he(label)}</a>')
        if dashboards:
            out.append(
                "    <p style='font-size:12px;color:#7f8c8d;margin:10px 0 4px'>"
                "Dashboards:</p>"
            )
            for label, url in dashboards:
                out.append(f'    <a href="{_he(url)}" class="dlink">&rarr; {_he(label)}</a>')

    out.append(f"""  </div>
  <div class="footer">
    Generated by sre-agent &nbsp;&middot;&nbsp;
    <a href="http://localhost:8081/incidents/{incident_id}">View incident</a>
    &nbsp;&middot;&nbsp;
    <a href="http://localhost:8081/incidents">All incidents</a>
  </div>
</div>
</body>
</html>""")

    return "\n".join(out)


# ── Evidence extraction ───────────────────────────────────────────────────────

def _ev_text(packet: dict[str, Any] | None) -> list[str]:
    if not packet:
        return ["  Evidence not yet collected."]
    metrics = packet.get("metrics", {})
    lines: list[str] = []

    def _rng(key: str, label: str, fmt):
        b = metrics.get(key, {})
        if b.get("status") != "ok":
            return
        s = b.get("summary", {})
        lines.append(f"  {label:<38} avg={fmt(s.get('avg'))}  max={fmt(s.get('max'))}")

    def _inst(key: str, label: str, fmt):
        b = metrics.get(key, {})
        if b.get("status") != "ok":
            return
        v = b.get("value")
        if v is not None:
            lines.append(f"  {label:<38} {fmt(v)}")

    _rng("cpu",               "CPU usage",              _fc)
    _rng("memory",            "Memory working set",     _fm)
    _rng("restarts",          "Restart increase (1h)",  _fn)
    _rng("flaky_error_rate",  "flaky-api error rate",   _fp)
    _rng("flaky_p95_latency", "flaky-api p95 latency",  _fms)
    _rng("flaky_request_rate","flaky-api request rate", _frps)
    _inst("flaky_injected_error_rate", "Injected error rate",   _fp)
    _inst("flaky_injected_latency_ms", "Injected latency (ms)", _fms_raw)

    errs = packet.get("errors", [])
    if errs:
        lines.append(f"  Collection errors: {'; '.join(errs)}")
    return lines or ["  No metric data available."]


def _ev_html(packet: dict[str, Any] | None) -> list[str]:
    if not packet:
        return ["<em>Evidence not yet collected.</em>"]
    metrics = packet.get("metrics", {})
    blocks: list[str] = []

    def _rng(key: str, label: str, fmt):
        b = metrics.get(key, {})
        if b.get("status") != "ok":
            return
        s = b.get("summary", {})
        blocks.append(
            f"<strong>{_he(label)}</strong> &nbsp;"
            f" avg <code>{fmt(s.get('avg'))}</code>"
            f" &nbsp; max <code>{fmt(s.get('max'))}</code>"
            f" &nbsp; last <code>{fmt(s.get('last'))}</code>"
        )

    def _inst(key: str, label: str, fmt):
        b = metrics.get(key, {})
        if b.get("status") != "ok":
            return
        v = b.get("value")
        if v is not None:
            blocks.append(
                f"<strong>{_he(label)}</strong> &nbsp; <code>{fmt(v)}</code> (live)"
            )

    _rng("cpu",               "CPU usage (cores)",      _fc)
    _rng("memory",            "Memory working set",     _fm)
    _rng("restarts",          "Restart increase (1h)",  _fn)
    _rng("flaky_error_rate",  "flaky-api error rate",   _fp)
    _rng("flaky_p95_latency", "flaky-api p95 latency",  _fms)
    _rng("flaky_request_rate","flaky-api request rate", _frps)
    _inst("flaky_injected_error_rate", "Injected error rate",   _fp)
    _inst("flaky_injected_latency_ms", "Injected latency (ms)", _fms_raw)

    return blocks or ["<em>No metric data available.</em>"]


# ── Grafana link extraction ───────────────────────────────────────────────────

def _gl_text(gl: dict[str, Any] | None) -> list[str]:
    if not gl:
        return []
    lines: list[str] = []
    for item in gl.get("explore", []):
        lines += [f"  [{item.get('label','')}]", f"  {item.get('url','')}"]
    for item in gl.get("dashboards", []):
        lines.append(f"  {item.get('label','')} — {item.get('url','')}")
    return lines


def _gl_html(
    gl: dict[str, Any] | None,
) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    if not gl:
        return [], []
    return (
        [(i.get("label", ""), i.get("url", "")) for i in gl.get("explore", [])],
        [(i.get("label", ""), i.get("url", "")) for i in gl.get("dashboards", [])],
    )


# ── Value formatters ──────────────────────────────────────────────────────────

def _fc(v):    return f"{v:.4f} cores" if v is not None else "n/a"
def _fm(v):    return f"{v/1_048_576:.1f} MiB" if v is not None else "n/a"
def _fn(v):    return f"{v:.1f}" if v is not None else "n/a"
def _fp(v):    return f"{v*100:.1f}%" if v is not None else "n/a"
def _fms(v):   return f"{v*1000:.0f} ms" if v is not None else "n/a"
def _fms_raw(v): return f"{v:.0f} ms" if v is not None else "n/a"
def _frps(v):  return f"{v:.2f} req/s" if v is not None else "n/a"


def _fmt_dt(dt: str | datetime) -> str:
    if isinstance(dt, datetime):
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    try:
        return datetime.fromisoformat(str(dt)).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(dt)


def _he(s: str) -> str:
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _sanitize_obj(value: Any) -> Any:
    if value is None:
        return None
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
