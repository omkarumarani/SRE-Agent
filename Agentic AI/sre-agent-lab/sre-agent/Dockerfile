# ── Build stage ───────────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM python:3.11-slim

LABEL org.opencontainers.image.title="sre-agent" \
      org.opencontainers.image.description="Alertmanager webhook receiver and incident store" \
      org.opencontainers.image.version="1.0.0"

# Non-root user
RUN useradd --create-home --shell /bin/bash appuser

# /data is the SQLite mount point — create it so the bind-mount is owned correctly
RUN mkdir /data && chown appuser:appuser /data

WORKDIR /app

COPY --from=builder /install /usr/local
COPY *.py ./

USER appuser

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
    CMD python3 -c \
        "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" \
    || exit 1

ENV PORT=8080 \
    DB_PATH=/data/sre_agent.db \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

CMD ["python3", "main.py"]
