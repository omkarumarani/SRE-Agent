"""
test_sensitive_data_guard.py — Unit tests for sensitive_data_guard.py

Run with:
    python -m pytest sre-agent/test_sensitive_data_guard.py -v
or from inside sre-agent/:
    python -m pytest test_sensitive_data_guard.py -v

No external dependencies required beyond pytest.
"""

from __future__ import annotations

import importlib
import os
import sys
import types
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import sensitive_data_guard as sdg

P = sdg.PLACEHOLDER   # "[REDACTED]"


# ---------------------------------------------------------------------------
# Helper: reload module with temporary env var overrides
# ---------------------------------------------------------------------------

import contextlib

@contextlib.contextmanager
def _env(**env_overrides):
    """Context manager: set env vars, yield, restore."""
    original = {k: os.environ.get(k) for k in env_overrides}
    for k, v in env_overrides.items():
        os.environ[k] = v
    try:
        yield
    finally:
        for k, orig in original.items():
            if orig is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = orig


# ===========================================================================
# 1. Tokens / API keys / bearer strings
# ===========================================================================

class TestTokenRedaction(unittest.TestCase):

    def test_bearer_token_in_header(self):
        text = "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.abc.def"
        out  = sdg.redact(text)
        self.assertNotIn("eyJhbG", out)
        self.assertIn(P, out)

    def test_bearer_lowercase(self):
        out = sdg.redact("auth: bearer abc123xyz9876543210ABCD")
        self.assertIn(P, out)

    def test_authorization_basic(self):
        out = sdg.redact("Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=")
        self.assertIn(P, out)
        self.assertNotIn("dXNlcm5hbWU6cGFzc3dvcmQ=", out)

    def test_api_key_kv_pair(self):
        out = sdg.redact("api_key=sk-abcdefghijklmnopqrstuvwxyz123456")
        self.assertIn(P, out)
        self.assertNotIn("sk-abcdef", out)

    def test_token_kv_pair(self):
        out = sdg.redact("token=ghp_1234567890abcdefGHIJKLMNOP")
        self.assertIn(P, out)

    def test_secret_kv_pair(self):
        out = sdg.redact("secret=mysupersecretvalue123")
        self.assertIn(P, out)

    def test_password_equals(self):
        out = sdg.redact("password=hunter2")
        self.assertIn(P, out)
        self.assertNotIn("hunter2", out)

    def test_password_colon(self):
        out = sdg.redact("password: correct-horse-battery-staple")
        self.assertIn(P, out)
        self.assertNotIn("correct-horse", out)

    def test_long_hex_token(self):
        out = sdg.redact("token: a3f5b8c2e1d9047f6a8b3c5d2e4f708192a3b4c5")
        self.assertIn(P, out)

    def test_jwt_token(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        out = sdg.redact(f"Authorization: Bearer {jwt}")
        self.assertIn(P, out)
        self.assertNotIn("eyJhbGci", out)

    def test_private_key_label(self):
        labels = {"private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEo..."}
        out = sdg.redact_dict(labels)
        self.assertEqual(out["private_key"], P)

    def test_normal_label_untouched(self):
        labels = {"alertname": "HighCPU", "severity": "critical"}
        out = sdg.redact_dict(labels)
        self.assertEqual(out, labels)


# ===========================================================================
# 2. Password redaction
# ===========================================================================

class TestPasswordRedaction(unittest.TestCase):

    def test_passwd_kv(self):
        out = sdg.redact("passwd=s3cr3tP@ss!")
        self.assertIn(P, out)

    def test_pwd_kv(self):
        out = sdg.redact("pwd=MyP@ssw0rd")
        self.assertIn(P, out)

    def test_sensitive_dict_key_password(self):
        d   = {"password": "letmein", "host": "db.internal"}
        out = sdg.redact_dict(d)
        self.assertEqual(out["password"], P)
        self.assertEqual(out["host"], "db.internal")

    def test_sensitive_dict_key_token(self):
        d   = {"token": "tok_live_abcdef123456", "service": "payments"}
        out = sdg.redact_dict(d)
        self.assertEqual(out["token"], P)
        self.assertEqual(out["service"], "payments")

    def test_empty_password_not_redacted(self):
        d   = {"password": ""}
        out = sdg.redact_dict(d)
        self.assertEqual(out["password"], "")

    def test_credential_key(self):
        d   = {"credentials": "user:pass"}
        out = sdg.redact_dict(d)
        self.assertEqual(out["credentials"], P)


# ===========================================================================
# 3. Email address redaction
# ===========================================================================

class TestEmailRedaction(unittest.TestCase):

    def test_plain_email(self):
        out = sdg.redact("Contact alice@example.com for details")
        self.assertNotIn("alice@example.com", out)
        self.assertIn(P, out)
        self.assertIn("Contact", out)
        self.assertIn("for details", out)

    def test_email_in_annotation(self):
        d   = {"description": "Alert sent by ops@company.io for review"}
        out = sdg.redact_dict(d)
        self.assertNotIn("ops@company.io", out["description"])
        self.assertIn(P, out["description"])

    def test_multiple_emails(self):
        text = "From: a@b.com  To: c@d.org  CC: e@f.net"
        out  = sdg.redact(text)
        for email in ("a@b.com", "c@d.org", "e@f.net"):
            self.assertNotIn(email, out)
        self.assertEqual(out.count(P), 3)

    def test_uppercase_email(self):
        out = sdg.redact("Owner: Alice.Smith@Corp.COM")
        self.assertNotIn("Alice.Smith@Corp.COM", out)
        self.assertIn(P, out)


# ===========================================================================
# 4. Phone number redaction
# ===========================================================================

class TestPhoneRedaction(unittest.TestCase):

    def test_us_phone_dashes(self):
        out = sdg.redact("Call 555-867-5309 for support")
        self.assertNotIn("867-5309", out)
        self.assertIn(P, out)

    def test_us_phone_dots(self):
        out = sdg.redact("Phone: 212.555.1234")
        self.assertIn(P, out)

    def test_e164_international(self):
        out = sdg.redact("Mobile +14155552671")
        self.assertIn(P, out)

    def test_phone_with_parens(self):
        out = sdg.redact("(800) 555-0199")
        self.assertIn(P, out)

    def test_short_number_not_redacted(self):
        out = sdg.redact("port=9090  timeout=30")
        self.assertNotIn(P, out)

    def test_metric_value_not_redacted(self):
        out = sdg.redact("latency_ms=1234")
        self.assertNotIn(P, out)


# ===========================================================================
# 5. IP address redaction (optional, env-var gated)
# ===========================================================================

class TestIPRedaction(unittest.TestCase):

    def test_ipv4_not_redacted_by_default(self):
        with _env(REDACT_IP="false"):
            out = sdg.redact("instance=192.168.1.100:9090")
        self.assertNotIn(P, out)

    def test_ipv4_redacted_when_enabled(self):
        with _env(REDACT_IP="true"):
            out = sdg.redact("host=10.0.0.1 port=8080")
        self.assertIn(P, out)
        self.assertNotIn("10.0.0.1", out)

    def test_ipv6_redacted_when_enabled(self):
        with _env(REDACT_IP="true"):
            out = sdg.redact("addr=2001:db8:85a3::8a2e:370:7334")
        self.assertIn(P, out)
        self.assertNotIn("2001:db8", out)

    def test_redact_ip_true_variants(self):
        for val in ("1", "yes", "true", "TRUE"):
            with _env(REDACT_IP=val):
                self.assertTrue(sdg._redact_ip(),
                    f"_redact_ip() should be True for REDACT_IP='{val}'")

    def test_redact_ip_false_variants(self):
        for val in ("0", "no", "false", "FALSE"):
            with _env(REDACT_IP=val):
                self.assertFalse(sdg._redact_ip(),
                    f"_redact_ip() should be False for REDACT_IP='{val}'")


# ===========================================================================
# 6. Log-line prefix stripping
# ===========================================================================

class TestLogLineStripping(unittest.TestCase):

    def test_iso_timestamp_prefix_stripped(self):
        line = "2024-03-15T10:22:33Z INFO app - user logged in"
        out  = sdg.redact(line)
        self.assertNotIn("2024-03-15", out)
        self.assertIn("user logged in", out)

    def test_log_with_secret_after_stripping(self):
        line = "2024-01-01 12:00:00 WARN api - token=supersecrettoken123456"
        out  = sdg.redact(line)
        self.assertNotIn("supersecrettoken123456", out)
        self.assertIn(P, out)

    def test_multiline_log(self):
        text = (
            "2024-03-15 10:00:00 INFO request received\n"
            "2024-03-15 10:00:00 ERROR password=badpass123\n"
        )
        out = sdg.redact(text)
        self.assertNotIn("badpass123", out)
        self.assertIn(P, out)

    def test_non_log_line_untouched(self):
        text = "container=flaky-api  severity=critical"
        out  = sdg.redact(text)
        self.assertIn("flaky-api", out)
        self.assertIn("critical", out)


# ===========================================================================
# 7. guard() — combined labels + annotations
# ===========================================================================

class TestGuard(unittest.TestCase):

    def test_guard_returns_tuple(self):
        result = sdg.guard({"alertname": "X"}, {"summary": "Y"})
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)

    def test_guard_cleans_both_dicts(self):
        labels = {
            "alertname": "HighCPU",
            "token": "tok_live_abc123456789xyz",
        }
        annotations = {
            "summary":     "Alert from admin@example.com",
            "description": "password=hunter2 caused the issue",
        }
        clean_labels, clean_annotations = sdg.guard(labels, annotations)
        self.assertEqual(clean_labels["alertname"], "HighCPU")
        self.assertEqual(clean_labels["token"], P)
        self.assertNotIn("admin@example.com", clean_annotations["summary"])
        self.assertNotIn("hunter2", clean_annotations["description"])

    def test_guard_empty_dicts(self):
        cl, ca = sdg.guard({}, {})
        self.assertEqual(cl, {})
        self.assertEqual(ca, {})

    def test_guard_non_string_values_pass_through(self):
        labels = {"severity": "critical", "count": 42, "active": True}
        cl, _ = sdg.guard(labels, {})
        self.assertEqual(cl["count"], 42)
        self.assertEqual(cl["active"], True)

    def test_guard_preserves_safe_prometheus_labels(self):
        labels = {
            "alertname":      "ContainerRestarts",
            "container_name": "flaky-api",
            "job":            "cadvisor",
            "severity":       "critical",
            "instance":       "cadvisor:8080",
        }
        cl, _ = sdg.guard(labels, {})
        for k, v in labels.items():
            self.assertEqual(cl[k], v, f"Label '{k}' should not be redacted")


# ===========================================================================
# 8. redact_dict — sensitive key coverage + edge cases
# ===========================================================================

class TestRedactDict(unittest.TestCase):

    def test_all_sensitive_key_names(self):
        sensitive_keys = [
            "password", "passwd", "pwd", "pass",
            "secret", "secrets",
            "token", "tokens", "access_token", "refresh_token", "id_token",
            "api_key", "apikey", "api_secret",
            "private_key", "priv_key",
            "auth", "authorization",
            "credential", "credentials", "cred", "creds",
            "bearer",
            "x-api-key", "x-auth-token", "x-access-token",
        ]
        for key in sensitive_keys:
            d   = {key: "somevalue123"}
            out = sdg.redact_dict(d)
            self.assertEqual(out[key], P, f"Key '{key}' should be redacted")

    def test_case_insensitive_key_match(self):
        for key in ("Password", "PASSWORD", "Token", "SECRET"):
            d   = {key: "mysecret"}
            out = sdg.redact_dict(d)
            self.assertEqual(out[key], P, f"Key '{key}' (case variant) should be redacted")

    def test_non_string_values_untouched(self):
        d   = {"count": 5, "ratio": 0.95, "enabled": False, "name": "test"}
        out = sdg.redact_dict(d)
        self.assertEqual(out["count"], 5)
        self.assertEqual(out["ratio"], 0.95)
        self.assertFalse(out["enabled"])
        self.assertEqual(out["name"], "test")

    def test_empty_string_value(self):
        d   = {"description": ""}
        out = sdg.redact_dict(d)
        self.assertEqual(out["description"], "")


# ===========================================================================
# 9. No false positives on typical Prometheus / alert data
# ===========================================================================

class TestNoFalsePositives(unittest.TestCase):

    def test_typical_alert_labels_unchanged(self):
        labels = {
            "alertname":      "HighContainerCPU",
            "container_name": "mem-leak",
            "image":          "ghcr.io/myorg/mem-leak:latest",
            "severity":       "warning",
            "job":            "cadvisor",
            "instance":       "cadvisor:8080",
        }
        cl, _ = sdg.guard(labels, {})
        for k, v in labels.items():
            self.assertEqual(cl[k], v, f"Label '{k}'='{v}' should not be redacted")

    def test_typical_annotation_unchanged(self):
        annotations = {
            "summary":     "Container mem-leak is using more than 500MiB of memory",
            "description": "Working set: 512MiB  limit: 512MiB  restarts: 3",
            "runbook_url": "https://docs.internal/runbooks/high-memory.md",
        }
        _, ca = sdg.guard({}, annotations)
        for k, v in annotations.items():
            self.assertEqual(ca[k], v, f"Annotation '{k}' should not be redacted")

    def test_version_string_not_redacted(self):
        out = sdg.redact("image=myapp:v2.14.0-rc1")
        self.assertNotIn(P, out)

    def test_duration_string_not_redacted(self):
        for val in ("30s", "5m", "2h", "1d"):
            out = sdg.redact(f"window={val}")
            self.assertNotIn(P, out, f"Duration '{val}' should not be redacted")

    def test_metric_name_not_redacted(self):
        text = "container_memory_working_set_bytes"
        out  = sdg.redact(text)
        self.assertNotIn(P, out)

    def test_runbook_url_not_redacted(self):
        text = "runbook_url=https://docs.internal/runbooks/high-cpu.md"
        out  = sdg.redact(text)
        self.assertNotIn(P, out)


# ===========================================================================
# 10. Real-world combined scenarios
# ===========================================================================

class TestRealWorldScenarios(unittest.TestCase):

    def test_mixed_safe_and_sensitive_annotation(self):
        ann = {
            "summary":     "HighCPU on flaky-api — contact ops@corp.com",
            "runbook_url": "https://docs.internal/runbooks/cpu.md",
            "token":       "tok_live_XYZ123abc456def",
        }
        _, ca = sdg.guard({}, ann)
        self.assertNotIn("ops@corp.com", ca["summary"])
        self.assertIn(P, ca["summary"])
        self.assertEqual(ca["runbook_url"], ann["runbook_url"])
        self.assertEqual(ca["token"], P)

    def test_log_line_with_email_and_token(self):
        line = (
            "2024-06-01T08:00:00Z ERROR auth - "
            "user admin@example.com failed: token=abc123xyz789def456ghi"
        )
        out = sdg.redact(line)
        self.assertNotIn("admin@example.com", out)
        self.assertNotIn("abc123xyz789def456ghi", out)
        self.assertIn("failed", out)

    def test_idempotent_redaction(self):
        sensitive = "password=hunter2  email=user@test.com"
        once  = sdg.redact(sensitive)
        twice = sdg.redact(once)
        self.assertEqual(once, twice)

    def test_github_pat_in_label(self):
        # key contains 'token' substring — should match sensitive key rule
        labels = {"repo_token": "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123"}
        out = sdg.redact_dict(labels)
        self.assertEqual(out["repo_token"], P)


if __name__ == "__main__":
    unittest.main(verbosity=2)
