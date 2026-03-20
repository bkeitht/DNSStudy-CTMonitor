## Architecture

DNSStudy-CTMonitor is the CT log monitoring infrastructure for the DNSStudy platform. It runs as a set of Docker containers on the same `dnsstudy-network` as the main DNSStudy-Mobile backend API.

### Components

- **certstream/** — Go-based CT log aggregator (fork of certstream-server-go). Connects to all active CT logs and streams certificate data over WebSocket.
- **ct-stream-filter/** — Python sidecar that consumes the certstream WebSocket firehose, matches certificates against watchlist patterns using Aho-Corasick, and writes alerts directly to PostgreSQL.
- **ct-watcher/** — CertSpotter CLI container that monitors specific domains from the watchlist and POSTs matches to the DNSStudy API ingest endpoint.

### Data Flow

```
CT Logs → certstream (WS :8080) → ct-stream-filter → PostgreSQL (ct_alerts)
CT Logs → ct-watcher (CertSpotter) → DNSStudy API → PostgreSQL (ct_alerts)
```

### Why Two Paths?

- **ct-stream-filter** handles the firehose (~175 certs/sec) with direct DB writes. It cannot use the API due to rate limiting and N+1 pattern loading overhead.
- **ct-watcher** uses CertSpotter for authoritative monitoring of specific domains. Low volume (~1-10/hour), safe to use the API ingest endpoint.

## Rules

- All containers run on the external `dnsstudy-network` Docker network.
- The sidecar writes directly to PostgreSQL — never route firehose traffic through the API.
- CertSpotter hook uses the API ingest endpoint (low volume, safe).
- Health reporting uses `POST /api/v1/ct-monitor/stream-state` (both components, ~2/min total).
- Pattern reload interval defaults to 300s — do not lower below 60s.

## Git Conventions

- Commit format: `<type>: <description>` (e.g., `feat: Add certstream container`)
- Types: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`, `perf`
- Branch naming: `<type>/<short-description>`
