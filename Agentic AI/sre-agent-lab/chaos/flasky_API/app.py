"""
flaky_api — chaos-ready HTTP service for sre-agent-lab
=======================================================

Control endpoints (all idempotent):
  POST /toggle_latency?ms=<n>       inject n ms of artificial delay  (0 = off)
  POST /toggle_error_rate?rate=<r>  inject error rate 0.0–1.0        (0 = off)
  POST /reset                       restore all defaults

Traffic endpoints (affected by injected faults):
  GET  /health                      liveness probe — always 200 unless force_error=true
  GET  /work                        simulated workload — respects latency + error injection

Observability:
  GET  /metrics                     Prometheus text exposition
"""

import logging
import os
import random
import time
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Query, Response
from fastapi.responses import JSONResponse, PlainTextResponse
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
log = logging.getLogger("flaky_api")

# ── Prometheus metrics ────────────────────────────────────────────────────────

REQUEST_COUNT = Counter(
    "flaky_api_requests",
    "Total HTTP requests handled",
    ["endpoint", "method", "status_code"],
)

ERROR_COUNT = Counter(
    "flaky_api_errors",
    "Total injected or real errors returned",
    ["endpoint", "error_type"],
)

REQUEST_LATENCY = Histogram(
    "flaky_api_request_duration_seconds",
    "End-to-end request latency including injected delay",
    ["endpoint"],
    buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
)

INJECTED_LATENCY_MS = Gauge(
    "flaky_api_injected_latency_ms",
    "Currently configured artificial latency in milliseconds",
)

INJECTED_ERROR_RATE = Gauge(
    "flaky_api_injected_error_rate",
    "Currently configured error injection rate (0.0–1.0)",
)

# ── Shared mutable state ──────────────────────────────────────────────────────
# Kept simple (in-process dict) — good enough for a single-replica lab service.

_state: dict = {
    "latency_ms": 0,
    "error_rate": 0.0,
}


def _current_state() -> dict:
    return {
        "latency_ms": _state["latency_ms"],
        "error_rate": _state["error_rate"],
    }


# ── Helper: inject configured latency ────────────────────────────────────────

async def _maybe_sleep() -> None:
    ms = _state["latency_ms"]
    if ms > 0:
        time.sleep(ms / 1000.0)   # blocking sleep is intentional — shows up in cAdvisor


# ── Helper: should this request fail? ─────────────────────────────────────────

def _should_error() -> bool:
    rate = _state["error_rate"]
    return rate > 0.0 and random.random() < rate


# ── App lifecycle ─────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("flaky_api starting — initial state: %s", _current_state())
    INJECTED_LATENCY_MS.set(0)
    INJECTED_ERROR_RATE.set(0)
    yield
    log.info("flaky_api shutting down")


app = FastAPI(
    title="flaky-api",
    description="Chaos-injectable HTTP service for sre-agent-lab",
    version="1.0.0",
    lifespan=lifespan,
)


# ── Traffic endpoints ─────────────────────────────────────────────────────────

@app.get("/health", summary="Liveness probe")
async def health():
    """
    Always returns 200 OK regardless of injected fault state.
    Use /work to exercise fault injection.
    """
    start = time.perf_counter()
    REQUEST_COUNT.labels("/health", "GET", "200").inc()
    REQUEST_LATENCY.labels("/health").observe(time.perf_counter() - start)
    return {"status": "ok", "injected": _current_state()}


@app.get("/work", summary="Simulated workload — respects injected faults")
async def work():
    """
    Simulates a real workload endpoint:
    - Sleeps for the configured artificial latency.
    - Returns HTTP 500 at the configured error rate.
    - Emits request_count, error_count, and latency_histogram metrics.
    """
    start = time.perf_counter()
    endpoint = "/work"

    await _maybe_sleep()

    if _should_error():
        duration = time.perf_counter() - start
        REQUEST_COUNT.labels(endpoint, "GET", "500").inc()
        ERROR_COUNT.labels(endpoint, "injected").inc()
        REQUEST_LATENCY.labels(endpoint).observe(duration)
        log.warning("/work returning injected 500 (rate=%.2f, latency_ms=%d)",
                    _state["error_rate"], _state["latency_ms"])
        return JSONResponse(
            status_code=500,
            content={
                "error": "injected failure",
                "injected": _current_state(),
            },
        )

    duration = time.perf_counter() - start
    REQUEST_COUNT.labels(endpoint, "GET", "200").inc()
    REQUEST_LATENCY.labels(endpoint).observe(duration)
    return {
        "status": "ok",
        "duration_ms": round(duration * 1000, 2),
        "injected": _current_state(),
    }


# ── Control endpoints ─────────────────────────────────────────────────────────

@app.post("/toggle_latency", summary="Set artificial response latency")
async def toggle_latency(ms: int = Query(default=0, ge=0, le=30_000,
                                          description="Latency in milliseconds (0 = off)")):
    """
    Injects a synchronous sleep of `ms` milliseconds into every /work request.
    Setting ms=0 disables latency injection.
    """
    _state["latency_ms"] = ms
    INJECTED_LATENCY_MS.set(ms)
    log.info("Latency injection set to %d ms", ms)
    return {"injected_latency_ms": ms, "state": _current_state()}


@app.post("/toggle_error_rate", summary="Set injected HTTP 500 error rate")
async def toggle_error_rate(rate: float = Query(default=0.0, ge=0.0, le=1.0,
                                                 description="Error rate 0.0–1.0 (0 = off, 1 = always fail)")):
    """
    Makes /work return HTTP 500 for approximately `rate` fraction of requests.
    Setting rate=0 disables error injection.
    """
    _state["error_rate"] = rate
    INJECTED_ERROR_RATE.set(rate)
    log.info("Error rate injection set to %.2f", rate)
    return {"injected_error_rate": rate, "state": _current_state()}


@app.post("/reset", summary="Clear all injected faults")
async def reset():
    """Resets latency and error rate back to zero."""
    _state["latency_ms"] = 0
    _state["error_rate"] = 0.0
    INJECTED_LATENCY_MS.set(0)
    INJECTED_ERROR_RATE.set(0.0)
    log.info("All fault injections cleared")
    return {"status": "reset", "state": _current_state()}


# ── Prometheus metrics endpoint ───────────────────────────────────────────────

@app.get("/metrics", include_in_schema=False)
async def metrics():
    """Standard Prometheus text exposition format."""
    return PlainTextResponse(
        content=generate_latest().decode("utf-8"),
        media_type=CONTENT_TYPE_LATEST,
    )


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
        log_level="info",
        access_log=True,
    )
