.PHONY: up down logs logs-certstream logs-filter logs-watcher status stats alerts rebuild test-ingest build

# --- Lifecycle ---

up:
	docker compose up -d

down:
	docker compose down

build:
	docker compose build

rebuild:
	docker compose build --no-cache
	docker compose up -d

# --- Logs ---

logs:
	docker compose logs -f --tail=100

logs-certstream:
	docker compose logs -f --tail=100 certstream

logs-filter:
	docker compose logs -f --tail=100 ct-stream-filter

logs-watcher:
	docker compose logs -f --tail=100 ct-watcher

# --- Monitoring ---

status:
	@curl -s http://localhost:8000/api/v1/ct-monitor/internal/status | python3 -m json.tool 2>/dev/null || echo "API not reachable"

stats:
	@curl -s http://localhost:8000/api/v1/ct-monitor/internal/stats | python3 -m json.tool 2>/dev/null || echo "API not reachable"

alerts:
	@curl -s http://localhost:8000/api/v1/ct-monitor/internal/alerts | python3 -m json.tool 2>/dev/null || echo "API not reachable"

# --- Testing ---

test-ingest:
	@curl -s -X POST http://localhost:8000/api/v1/ct-monitor/ingest/certificate \
		-H "Content-Type: application/json" \
		-d '{"fingerprint_sha256":"abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234","subject_cn":"test.example.com","san_entries":["test.example.com","*.example.com"],"issuer_name":"Test CA","issuer_organization":"Test Org","source":"certstream","is_precert":false}' \
		| python3 -m json.tool 2>/dev/null || echo "API not reachable"
