# sre-agent-lab

> A self-contained home lab for experimenting with AI-powered SRE workflows — alerting, incident response, chaos engineering, and automated remediation — running entirely on Docker Desktop (WSL2).

---

## Overview

`sre-agent-lab` provides a local, batteries-included observability and incident-response playground. It wires together:

- **Prometheus** — metrics collection and alerting rules
- **Alertmanager** — alert routing and notification (email via smtp4dev)
- **Grafana** — dashboards and datasource provisioning
- **smtp4dev** — local fake SMTP server for catching alert emails
- **sre-agent** — an LLM-powered agent that watches alerts and attempts automated remediation
- **chaos** — scripts and tooling to inject failures on demand

The goal is a realistic but entirely local environment where you can break things safely and watch an AI agent respond.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Windows 10/11 (22H2+) | WSL2 backend required |
| Docker Desktop ≥ 4.25 | Enable WSL2 integration in Settings → Resources → WSL Integration |
| WSL2 distro (Ubuntu 22.04 recommended) | `wsl --install -d Ubuntu` |
| 8 GB RAM (16 GB recommended) | Allocate ≥ 4 GB to WSL2 in `.wslconfig` |
| Git | For cloning and config-repo operations |
| `make` (optional) | Convenience targets in `Makefile` |

**WSL2 memory config** — create or edit `C:\Users\<you>\.wslconfig`:
```ini
[wsl2]
memory=8GB
processors=4
```
Then restart WSL: `wsl --shutdown`.

---

## Quickstart

```bash
# 1. Clone the repo
git clone https://github.com/<you>/sre-agent-lab.git
cd sre-agent-lab

# 2. Copy and edit environment variables
cp .env.example .env
# Edit .env — set ANTHROPIC_API_KEY and any other secrets

# 3. Start the full stack
docker compose -f compose/docker-compose.yml up -d

# 4. Verify everything is healthy
docker compose -f compose/docker-compose.yml ps

# 5. Open the UIs
#   Grafana       → http://localhost:3000  (admin / admin)
#   Prometheus    → http://localhost:9090
#   Alertmanager  → http://localhost:9093
#   smtp4dev      → http://localhost:5000
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Docker Network                        │
│                                                             │
│  ┌───────────┐    scrape    ┌────────────┐                  │
│  │ Target(s) │◄────────────│ Prometheus │                   │
│  └───────────┘             └─────┬──────┘                   │
│                                  │ fire alerts              │
│                           ┌──────▼──────┐                   │
│                           │Alertmanager │                   │
│                           └──────┬──────┘                   │
│                 notify           │           notify         │
│           ┌─────────────┐        │      ┌────────────────┐  │
│           │  smtp4dev   │◄───────┴─────►│   sre-agent    │  │
│           │  (UI :5000) │              │  (LLM + tools) │  │
│           └─────────────┘              └────────────────┘  │
│                                                             │
│  ┌─────────────────────────────┐                            │
│  │  Grafana (dashboards :3000) │◄── Prometheus datasource   │
│  └─────────────────────────────┘                            │
└─────────────────────────────────────────────────────────────┘

chaos/ scripts inject failures → metrics degrade → alerts fire → agent remediates
```

**Directory layout:**

```
sre-agent-lab/
├── compose/                  # docker-compose.yml and service overrides
├── prometheus/               # prometheus.yml, alert rules (*.rules.yml)
├── alertmanager/             # alertmanager.yml routing config
├── grafana/
│   └── provisioning/
│       ├── datasources/      # Prometheus datasource YAML
│       └── dashboards/       # Dashboard JSON + dashboard.yml provider
├── sre-agent/                # Agent source code, Dockerfile, prompts
├── chaos/                    # Chaos scripts (CPU spike, OOM, latency injection)
├── config-repo/              # GitOps-style config watched by agent
└── docs/                     # Architecture diagrams, runbooks, ADRs
```

---

## How to Trigger Incidents

Use the scripts in `chaos/` to inject failures into the running stack.

### CPU Spike
```bash
# Peg one container to 95% CPU for 60 seconds
bash chaos/cpu_spike.sh --target app --duration 60
```

### Memory Pressure
```bash
# Gradually allocate memory until OOM or threshold
bash chaos/mem_pressure.sh --target app --limit 512m
```

### HTTP Latency / Error Injection
```bash
# Add 2 s latency to all outbound calls from a service
bash chaos/latency_inject.sh --target app --delay 2000ms

# Return 500s on 30% of requests
bash chaos/error_inject.sh --target app --rate 0.3
```

### Manual Alert
```bash
# POST a fake alert directly to Alertmanager
curl -X POST http://localhost:9093/api/v2/alerts \
  -H 'Content-Type: application/json' \
  -d '[{
    "labels": {"alertname":"HighErrorRate","severity":"critical","service":"app"},
    "annotations": {"summary":"Manually triggered test alert"},
    "generatorURL": "http://localhost:9090"
  }]'
```

After triggering, watch the **sre-agent** logs for remediation steps:
```bash
docker compose -f compose/docker-compose.yml logs -f sre-agent
```

---

## How to View Emails in smtp4dev

smtp4dev acts as a local catch-all SMTP server — no real emails are ever sent.

1. Open **http://localhost:5000** in your browser.
2. All alert emails routed by Alertmanager appear in the inbox automatically.
3. Click any message to inspect headers, body, and HTML rendering.
4. Use the **Delete all** button to clear the inbox between tests.

**Alertmanager is pre-configured** to send to `smtp4dev` — see `alertmanager/alertmanager.yml`:
```yaml
smtp_smarthost: 'smtp4dev:25'
smtp_from: 'alertmanager@lab.local'
smtp_require_tls: false
```

---

## Next Steps (Level 2 / Level 3)

### Level 2 — Extend the Lab

- [ ] Add a **service mesh** (e.g., Linkerd) to get golden-signal metrics for free
- [ ] Integrate **Loki + Promtail** for log aggregation; give the agent log-search tools
- [ ] Write custom **Prometheus recording rules** to reduce query cardinality
- [ ] Add **PagerDuty / Slack webhook** receivers alongside smtp4dev
- [ ] Build a **runbook library** in `docs/` and have the agent reference them
- [ ] Parameterise chaos scripts with **Toxiproxy** for network-layer failures
- [ ] Add **Jaeger** or **Tempo** for distributed tracing

### Level 3 — Production Patterns

- [ ] Replace local `sre-agent` with an **Anthropic Claude API**-backed agent using tool use
- [ ] Implement **GitOps remediation** — agent opens PRs against `config-repo/`
- [ ] Add **approval gates** — agent proposes a fix, human approves via Slack reaction
- [ ] Introduce **multi-agent coordination** (triage agent → remediation agent → postmortem agent)
- [ ] Export lab metrics to a **hosted Grafana Cloud** free tier for persistence
- [ ] Package the stack as a **Helm chart** and migrate to a local k3s/Kind cluster
- [ ] Write **automated chaos game days** that run on a schedule and score agent performance

---

*Happy breaking things. 🔥*
