"""
db.py — async SQLite database layer for sre-agent.

Schema
──────
incidents
  id               INTEGER PRIMARY KEY AUTOINCREMENT
  created_at       TEXT     ISO-8601 UTC
  updated_at       TEXT     ISO-8601 UTC
  status           TEXT     "open" | "resolved" | "acknowledged"
  alertname        TEXT
  severity         TEXT
  service          TEXT
  container_name   TEXT
  summary          TEXT
  labels           TEXT     JSON blob
  annotations      TEXT     JSON blob
  raw_alert_hash   TEXT     SHA-256 of the raw alert fingerprint + labels
  evidence_path    TEXT     Path to evidence JSON file (may be empty)

incident_timeline
  id               INTEGER PRIMARY KEY AUTOINCREMENT
  incident_id      INTEGER  FK → incidents.id
  created_at       TEXT     ISO-8601 UTC
  event            TEXT     machine-readable label  e.g. "alert_received"
  detail           TEXT     human-readable description
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone

import aiosqlite

log = logging.getLogger("sre_agent.db")

DB_PATH = os.environ.get("DB_PATH", "/data/sre_agent.db")

# ── DDL ───────────────────────────────────────────────────────────────────────

_DDL = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS incidents (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at     TEXT    NOT NULL,
    updated_at     TEXT    NOT NULL,
    status         TEXT    NOT NULL DEFAULT 'open',
    alertname      TEXT    NOT NULL DEFAULT '',
    severity       TEXT    NOT NULL DEFAULT '',
    service        TEXT    NOT NULL DEFAULT '',
    container_name TEXT    NOT NULL DEFAULT '',
    summary        TEXT    NOT NULL DEFAULT '',
    labels         TEXT    NOT NULL DEFAULT '{}',
    annotations    TEXT    NOT NULL DEFAULT '{}',
    raw_alert_hash TEXT    NOT NULL DEFAULT '',
    evidence_path  TEXT    NOT NULL DEFAULT '',
    llm_response   TEXT    NOT NULL DEFAULT '',
    github_issue_url TEXT  NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_incidents_status
    ON incidents (status);

CREATE INDEX IF NOT EXISTS idx_incidents_alertname
    ON incidents (alertname);

CREATE TABLE IF NOT EXISTS incident_timeline (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    created_at  TEXT    NOT NULL,
    event       TEXT    NOT NULL,
    detail      TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_timeline_incident
    ON incident_timeline (incident_id);
"""

# Migration: add evidence_path to existing databases that pre-date this column.
_MIGRATE_EVIDENCE_PATH = """
ALTER TABLE incidents ADD COLUMN evidence_path TEXT NOT NULL DEFAULT '';
"""

_MIGRATE_LLM_RESPONSE = """
ALTER TABLE incidents ADD COLUMN llm_response TEXT NOT NULL DEFAULT '';
"""

_MIGRATE_GITHUB_ISSUE_URL = """
ALTER TABLE incidents ADD COLUMN github_issue_url TEXT NOT NULL DEFAULT '';
"""


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_alert(fingerprint: str, labels: dict) -> str:
    """Stable hash used to deduplicate re-fired alerts."""
    key = fingerprint + json.dumps(labels, sort_keys=True)
    return hashlib.sha256(key.encode()).hexdigest()


# ── Init ──────────────────────────────────────────────────────────────────────

async def init_db() -> None:
    """Create tables and run lightweight migrations. Called once at startup."""
    os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.executescript(_DDL)
        # Idempotent migration: add evidence_path if missing
        try:
            await conn.execute(_MIGRATE_EVIDENCE_PATH)
            await conn.commit()
            log.info("Migrated: added evidence_path column")
        except Exception:
            # Column already exists — ignore
            pass
        # Idempotent migration: add llm_response if missing
        try:
            await conn.execute(_MIGRATE_LLM_RESPONSE)
            await conn.commit()
            log.info("Migrated: added llm_response column")
        except Exception:
            # Column already exists — ignore
            pass
        # Idempotent migration: add github_issue_url if missing
        try:
            await conn.execute(_MIGRATE_GITHUB_ISSUE_URL)
            await conn.commit()
            log.info("Migrated: added github_issue_url column")
        except Exception:
            # Column already exists — ignore
            pass
    log.info("Database ready at %s", DB_PATH)


# ── Incident CRUD ─────────────────────────────────────────────────────────────

async def create_incident(
    alertname: str,
    severity: str,
    service: str,
    container_name: str,
    summary: str,
    labels: dict,
    annotations: dict,
    raw_alert_hash: str,
) -> int:
    """Insert a new incident row and return its id."""
    now = _now()
    async with aiosqlite.connect(DB_PATH) as conn:
        cur = await conn.execute(
            """
            INSERT INTO incidents
              (created_at, updated_at, status,
               alertname, severity, service, container_name, summary,
               labels, annotations, raw_alert_hash, evidence_path, llm_response, github_issue_url)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                now, now, "open",
                alertname, severity, service, container_name, summary,
                json.dumps(labels), json.dumps(annotations), raw_alert_hash,
                "",           # evidence_path populated after collection
                "",           # llm_response populated after LLM call
                "",           # github_issue_url populated after GitHub issue creation
            ),
        )
        await conn.commit()
        incident_id = cur.lastrowid
    log.info("Created incident #%d  alertname=%s", incident_id, alertname)
    return incident_id


async def update_incident_status(incident_id: int, status: str) -> None:
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute(
            "UPDATE incidents SET status=?, updated_at=? WHERE id=?",
            (status, _now(), incident_id),
        )
        await conn.commit()
    log.info("Incident #%d status → %s", incident_id, status)


async def update_evidence_path(incident_id: int, path: str) -> None:
    """Record the path to the evidence JSON file after collection."""
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute(
            "UPDATE incidents SET evidence_path=?, updated_at=? WHERE id=?",
            (path, _now(), incident_id),
        )
        await conn.commit()
    log.debug("Incident #%d evidence_path → %s", incident_id, path)


async def update_llm_response(incident_id: int, llm_response_json: str) -> None:
    """Store structured LLM response JSON for an incident."""
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute(
            "UPDATE incidents SET llm_response=?, updated_at=? WHERE id=?",
            (llm_response_json, _now(), incident_id),
        )
        await conn.commit()
    log.debug("Incident #%d llm_response updated", incident_id)


async def update_github_issue_url(incident_id: int, url: str) -> None:
    """Store GitHub issue URL for an incident."""
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute(
            "UPDATE incidents SET github_issue_url=?, updated_at=? WHERE id=?",
            (url, _now(), incident_id),
        )
        await conn.commit()
    log.debug("Incident #%d github_issue_url updated", incident_id)


async def get_incident_by_hash(raw_alert_hash: str) -> dict | None:
    """Return the most recent open incident matching this hash, or None."""
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute(
            """
            SELECT * FROM incidents
            WHERE raw_alert_hash = ? AND status = 'open'
            ORDER BY created_at DESC LIMIT 1
            """,
            (raw_alert_hash,),
        ) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None


async def get_incident(incident_id: int) -> dict | None:
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute(
            "SELECT * FROM incidents WHERE id = ?", (incident_id,)
        ) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None


async def list_incidents(
    limit: int = 50,
    offset: int = 0,
    status: str | None = None,
) -> list[dict]:
    query  = "SELECT * FROM incidents"
    params: list = []
    if status:
        query += " WHERE status = ?"
        params.append(status)
    query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params += [limit, offset]

    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute(query, params) as cur:
            rows = await cur.fetchall()
            return [dict(r) for r in rows]


async def count_incidents() -> int:
    async with aiosqlite.connect(DB_PATH) as conn:
        async with conn.execute("SELECT COUNT(*) FROM incidents") as cur:
            row = await cur.fetchone()
            return row[0] if row else 0


# ── Timeline CRUD ─────────────────────────────────────────────────────────────

async def add_timeline_entry(incident_id: int, event: str, detail: str = "") -> int:
    now = _now()
    async with aiosqlite.connect(DB_PATH) as conn:
        cur = await conn.execute(
            "INSERT INTO incident_timeline (incident_id, created_at, event, detail) VALUES (?,?,?,?)",
            (incident_id, now, event, detail),
        )
        await conn.commit()
        return cur.lastrowid


async def get_timeline(incident_id: int) -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute(
            "SELECT * FROM incident_timeline WHERE incident_id=? ORDER BY created_at ASC",
            (incident_id,),
        ) as cur:
            rows = await cur.fetchall()
            return [dict(r) for r in rows]


# ── Re-export helpers ─────────────────────────────────────────────────────────

def compute_hash(fingerprint: str, labels: dict) -> str:
    return _hash_alert(fingerprint, labels)
