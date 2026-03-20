# DNSStudy-CTMonitor

Container infrastructure for Certificate Transparency log monitoring, feeding certificate data into the [DNSStudy-Mobile](https://github.com/bkeitht/DNSStudy-Mobile) platform.

## Components

| Container | Purpose | Resource Limits |
|-----------|---------|-----------------|
| **certstream** | CT log aggregator (Go, WebSocket server on :8080) | 1 CPU, 512M RAM |
| **ct-stream-filter** | Firehose filter with Aho-Corasick matching → direct PostgreSQL writes | 1 CPU, 512M RAM |
| **ct-watcher** | CertSpotter CLI → API ingest for authoritative domain monitoring | 0.5 CPU, 256M RAM |

## Prerequisites

- Docker and Docker Compose
- `dnsstudy-network` Docker network exists (`docker network create dnsstudy-network`)
- DNSStudy-Mobile backend API running on the same network
- PostgreSQL accessible on the same network

## Quick Start

```bash
cp .env.example .env
# Edit .env with your PostgreSQL credentials and API URL

make build
make up
make status
```

## Commands

```bash
make up          # Start all containers
make down        # Stop all containers
make logs        # Tail all logs
make status      # Show component health
make stats       # Show alert statistics
make alerts      # List recent alerts
make test-ingest # Send a test certificate event
```

## Network Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   dnsstudy-network                       │
│                                                          │
│  ┌──────────┐    WS     ┌──────────────────┐            │
│  │certstream├───────────►│ct-stream-filter  │            │
│  │  :8080   │           │(Aho-Corasick)    │            │
│  └──────────┘           └────────┬─────────┘            │
│                                  │ direct INSERT         │
│  ┌──────────┐    API    ┌───────┴──────────┐            │
│  │ct-watcher├──────────►│  dnsstudy-api    │            │
│  │(CertSpot)│  ingest   │     :8000        │            │
│  └──────────┘           └────────┬─────────┘            │
│                                  │                       │
│                         ┌────────▼─────────┐            │
│                         │   PostgreSQL     │            │
│                         │   (ct_alerts)    │            │
│                         └──────────────────┘            │
└─────────────────────────────────────────────────────────┘
```

## Integration with DNSStudy-Mobile

| Endpoint | Used By | Rate |
|----------|---------|------|
| `POST /api/v1/ct-monitor/ingest/certificate` | ct-watcher hook | ~1-10/hour |
| `POST /api/v1/ct-monitor/stream-state` | ct-stream-filter, ct-watcher | ~2/min |
| `GET /api/v1/ct-monitor/watchlist/file` | ct-watcher entrypoint | ~1/5min |
| PostgreSQL `ct_watchlist` (SELECT) | ct-stream-filter | 1/5min |
| PostgreSQL `ct_alerts` (INSERT) | ct-stream-filter | ~1-100/sec |
