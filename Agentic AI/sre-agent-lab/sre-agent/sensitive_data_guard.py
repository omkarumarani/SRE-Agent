"""
sensitive_data_guard.py — SensitiveDataGuard for sre-agent.

Redacts sensitive patterns from strings and dicts before they are:
  - stored in SQLite (alert labels / annotations / summaries)
  - sent over email (notifier.py)

Redacted patterns
─────────────────
Always redacted:
  • API keys / tokens / secrets — key=<value>, token=<value>,
    bearer <value>, Authorization: Basic/Bearer <value>,
    high-entropy bare tokens (hex ≥ 20 chars, base64url ≥ 24 chars)
  • Passwords — password=<value>, passwd=<value>, pwd=<value>
  • Email addresses
  • Phone numbers — E.164, North American, common separators

Optionally redacted (env var):
  • IPv4 addresses        REDACT_IP=true   (default: false)
  • IPv6 addresses        REDACT_IP=true

Log-like raw text scrubbing:
  • Lines that start with a recognisable timestamp AND/OR log-level keyword
    have that prefix stripped before redaction.  A bare English word is NOT
    treated as a log prefix (fixes false stripping of "Container", "Contact").

Configuration
─────────────
REDACT_IP    "true" / "1" / "yes"  to redact IP addresses.   default: false

Public API
──────────
redact(text: str) -> str
redact_dict(d: dict) -> dict
guard(labels: dict, annotations: dict) -> tuple[dict, dict]
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any

log = logging.getLogger("sre_agent.sdg")

PLACEHOLDER = "[REDACTED]"

# ── Runtime flag (read on every call so env changes in tests take effect) ──────

def _redact_ip() -> bool:
    return os.environ.get("REDACT_IP", "false").lower() in ("true", "1", "yes")

# Expose as module attribute for test introspection — reflects current env.
@property
def _REDACT_IP_PROP(self):  # noqa: N802
    return _redact_ip()

# Simple module-level bool updated via reload (tests use importlib.reload)
REDACT_IP: bool = _redact_ip()

# ── Sensitive key names ────────────────────────────────────────────────────────

_SENSITIVE_KEY_RE = re.compile(
    r"(?i)^("
    r"password|passwd|pwd|pass"
    r"|secret|secrets"
    r"|token|tokens|access_token|refresh_token|id_token"
    r"|api_key|apikey|api_secret"
    r"|private_key|priv_key"
    r"|auth|authorization"
    r"|credential|credentials|cred|creds"
    r"|bearer"
    r"|x-api-key|x-auth-token|x-access-token"
    r")$"
)

# ── Per-value regex patterns ───────────────────────────────────────────────────

# Authorization / Bearer header — matches Basic, Bearer, Token, Digest schemes
_BEARER_RE = re.compile(
    r"(?i)"
    r"(authorization\s*:\s*(?:bearer|basic|token|digest)\s+"
    r"|bearer\s+)"
    r"([A-Za-z0-9\-_.~+/=]{8,})",
)

# key=value or key: value for common secret field names in free text.
# Value may contain hyphens, dots, underscores (e.g. correct-horse-battery-staple).
_KV_SECRET_RE = re.compile(
    r"(?i)"
    r"(password|passwd|pwd|pass"
    r"|secret|token|api[_\-]?key|private[_\-]?key"
    r"|credential|auth)"
    r"\s*[:=]\s*"
    r"([^\s,;&'\"]{4,})",
)

# High-entropy hex tokens (≥ 20 hex chars)
_HEX_TOKEN_RE = re.compile(r"\b[0-9a-fA-F]{20,}\b")

# High-entropy base64url tokens (≥ 24 mixed chars)
_B64_TOKEN_RE = re.compile(r"\b[A-Za-z0-9+/\-_]{24,}={0,2}\b")

# Email addresses
_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
)

# Phone numbers (E.164, North American, common separators)
_PHONE_RE = re.compile(
    r"(?<!\d)"
    r"(\+?1[\s.\-]?)?"
    r"\(?\d{3}\)?[\s.\-]?"
    r"\d{3}[\s.\-]?"
    r"\d{4}"
    r"(?!\d)"
)

# IPv4
_IPV4_RE = re.compile(
    r"\b"
    r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
    r"\b"
)

# IPv6 (simplified)
_IPV6_RE = re.compile(
    r"(?<![:\w])"
    r"(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}"
    r"|::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}::"
    r"(?![\w:])"
)

# Log-line timestamp (required anchor for log-prefix stripping)
_TIMESTAMP_RE = re.compile(
    r"^\s*\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"
    r"(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?\s*"
)

# Log level keyword (only meaningful after a timestamp OR at line start
# when immediately followed by more content)
_LEVEL_RE = re.compile(
    r"^\[?(?:DEBUG|INFO|WARN(?:ING)?|ERROR|CRITICAL|FATAL|TRACE)\]?\s+",
    re.IGNORECASE,
)

# Optional logger name after level (word chars / dots / colons followed by space)
_LOGGER_RE = re.compile(r"^[A-Za-z0-9_.:\-]+\s+")


# ── Public API ────────────────────────────────────────────────────────────────

def redact(text: str) -> str:
    """
    Redact all sensitive patterns from *text* and return the cleaned string.

    Processing order:
      1. Strip raw log-line prefix (timestamp + optional level + logger).
      2. Redact Authorization / Bearer header values.
      3. Redact key=value secret pairs in free text.
      4. Redact email addresses.
      5. Redact phone numbers.
      6. Optionally redact IPv4 / IPv6 (controlled by REDACT_IP env var).
      7. Redact high-entropy hex tokens.
      8. Redact high-entropy base64url tokens.
    """
    if not isinstance(text, str) or not text.strip():
        return text

    out = _strip_log_prefix(text)
    out = _BEARER_RE.sub(lambda m: m.group(1) + PLACEHOLDER, out)
    out = _KV_SECRET_RE.sub(lambda m: m.group(1) + "=" + PLACEHOLDER, out)
    out = _EMAIL_RE.sub(PLACEHOLDER, out)
    out = _PHONE_RE.sub(_replace_phone, out)

    if _redact_ip():
        out = _IPV6_RE.sub(PLACEHOLDER, out)
        out = _IPV4_RE.sub(PLACEHOLDER, out)

    out = _HEX_TOKEN_RE.sub(_replace_hex, out)
    out = _B64_TOKEN_RE.sub(_replace_b64, out)

    return out


def redact_dict(d: dict[str, Any]) -> dict[str, Any]:
    """
    Redact every value in a flat dict.

    - If the key matches _SENSITIVE_KEY_RE the entire value is replaced.
    - Otherwise the value is passed through redact().
    - Non-string values (int, bool, None) are passed through unchanged.
    """
    if not d:
        return d
    out: dict[str, Any] = {}
    for k, v in d.items():
        if not isinstance(v, str):
            out[k] = v
            continue
        if _SENSITIVE_KEY_RE.match(str(k)):
            out[k] = PLACEHOLDER if v else v
            if v:
                log.debug("SDG: redacted sensitive key '%s'", k)
        else:
            cleaned = redact(v)
            if cleaned != v:
                log.debug("SDG: redacted value for key '%s'", k)
            out[k] = cleaned
    return out


def guard(
    labels:      dict[str, Any],
    annotations: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """
    Primary entry point called from main.py before persistence / email.
    Returns (clean_labels, clean_annotations).
    """
    return redact_dict(labels), redact_dict(annotations)


# ── Internal helpers ──────────────────────────────────────────────────────────

def _strip_log_prefix(text: str) -> str:
    """
    Strip log-line prefix from each line in *text*.

    A prefix is only stripped when a line starts with:
      - A recognisable ISO timestamp  (required OR)
      - A log-level keyword at the very start of the line
        followed by more non-whitespace content

    A bare English word (e.g. "Container", "Contact") is NOT treated
    as a log prefix.
    """
    lines = text.splitlines(keepends=True)
    out = []
    for line in lines:
        stripped = _strip_one_line(line)
        out.append(stripped)
    return "".join(out) if out else text


def _strip_one_line(line: str) -> str:
    pos = 0

    # Try timestamp anchor first
    ts_match = _TIMESTAMP_RE.match(line)
    if ts_match:
        pos = ts_match.end()
        # Optionally consume a log level after the timestamp
        level_match = _LEVEL_RE.match(line, pos)
        if level_match:
            pos = level_match.end()
            # Optionally consume a logger name after the level
            logger_match = _LOGGER_RE.match(line, pos)
            if logger_match:
                pos = logger_match.end()
    else:
        # No timestamp — only strip if line starts with a level keyword
        level_match = _LEVEL_RE.match(line)
        if level_match:
            pos = level_match.end()
            logger_match = _LOGGER_RE.match(line, pos)
            if logger_match:
                pos = logger_match.end()

    # Only strip if we consumed something and there's still content left
    if pos > 0 and pos < len(line) and line[pos:].strip():
        return line[pos:]
    return line


def _replace_phone(m: re.Match) -> str:
    if len(re.sub(r"\D", "", m.group())) >= 10:
        return PLACEHOLDER
    return m.group()


def _replace_hex(m: re.Match) -> str:
    token = m.group()
    if len(token) >= 32:
        return PLACEHOLDER
    if not re.search(r"[g-zG-Z]", token):
        return PLACEHOLDER
    return token


def _replace_b64(m: re.Match) -> str:
    token = m.group()

    if re.fullmatch(r"[a-z_][a-z0-9_]*", token):
        return token
    if re.fullmatch(r"v?\d+[\d.\-\w]*", token):
        return token
    if re.fullmatch(r"\d+[smhd]", token):
        return token

    vowels = sum(1 for c in token.lower() if c in "aeiou")
    if len(token) < 30 and vowels / max(len(token), 1) > 0.30:
        return token

    has_upper   = bool(re.search(r"[A-Z]", token))
    has_lower   = bool(re.search(r"[a-z]", token))
    has_digit   = bool(re.search(r"\d", token))
    has_special = bool(re.search(r"[+/\-_=]", token))

    if sum([has_upper, has_lower, has_digit, has_special]) >= 3:
        return PLACEHOLDER

    return token
