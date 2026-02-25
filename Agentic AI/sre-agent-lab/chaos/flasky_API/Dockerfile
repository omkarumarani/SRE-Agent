# ── Build stage ───────────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# Install dependencies into an isolated prefix so we can copy only what we need
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM python:3.12-slim

LABEL org.opencontainers.image.title="flaky-api" \
      org.opencontainers.image.description="Chaos-injectable HTTP service for sre-agent-lab" \
      org.opencontainers.image.version="1.0.0"

# Non-root user for defence-in-depth
RUN useradd --create-home --shell /bin/bash appuser

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application source
COPY app.py .

# Drop to non-root
USER appuser

# Port the app listens on (can be overridden via PORT env var)
EXPOSE 8000

# Health check — Docker / Compose will mark the container unhealthy if /health fails
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD python3 -c \
        "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" \
    || exit 1

ENV PORT=8000 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

CMD ["python3", "app.py"]
