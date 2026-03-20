#!/usr/bin/env bash
set -euo pipefail

DNSSTUDY_API_URL="${DNSSTUDY_API_URL:-http://dnsstudy-api:8000}"
WATCHLIST_REFRESH_INTERVAL="${WATCHLIST_REFRESH_INTERVAL:-300}"
WATCHLIST_FILE="/tmp/watchlist.txt"
STATE_DIR="/var/lib/certspotter"

log() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) [INFO] $*"; }
warn() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) [WARN] $*" >&2; }

# Report initial state to API
report_state() {
    local status="$1"
    curl -sf -X POST "${DNSSTUDY_API_URL}/api/v1/ct-monitor/stream-state" \
        -H "Content-Type: application/json" \
        -d "{\"component\":\"certspotter\",\"status\":\"${status}\"}" \
        >/dev/null 2>&1 || warn "Failed to report state: ${status}"
}

# Fetch watchlist from API
fetch_watchlist() {
    log "Fetching watchlist from ${DNSSTUDY_API_URL}/api/v1/ct-monitor/watchlist/file"
    local http_code
    http_code=$(curl -sf -o "${WATCHLIST_FILE}" -w "%{http_code}" \
        "${DNSSTUDY_API_URL}/api/v1/ct-monitor/watchlist/file" 2>/dev/null) || true

    if [ "$http_code" != "200" ]; then
        warn "Watchlist fetch returned HTTP ${http_code:-error}"
        return 1
    fi

    # Check if file is empty or only whitespace
    if [ ! -s "${WATCHLIST_FILE}" ] || ! grep -q '[^[:space:]]' "${WATCHLIST_FILE}"; then
        warn "Watchlist is empty"
        return 1
    fi

    local count
    count=$(grep -c '[^[:space:]]' "${WATCHLIST_FILE}")
    log "Watchlist has ${count} entries"
    return 0
}

# Main loop: fetch watchlist, then run certspotter
main() {
    report_state "running"

    # Retry watchlist fetch until we get entries
    while true; do
        if fetch_watchlist; then
            break
        fi
        log "Retrying watchlist fetch in 60s..."
        sleep 60
    done

    log "Starting certspotter"
    log "Watching $(grep -c '[^[:space:]]' "${WATCHLIST_FILE}") domains"
    log "State directory: ${STATE_DIR}"

    # Run certspotter — it monitors CT logs continuously
    # -watchlist: file with one domain per line (dot-prefix = include subdomains)
    # -script: hook script called for each discovered certificate
    # -state_dir: persist progress for recovery after restart
    # -verbose: log activity
    exec certspotter \
        -watchlist "${WATCHLIST_FILE}" \
        -script /usr/local/bin/hook.sh \
        -state_dir "${STATE_DIR}" \
        -verbose
}

main "$@"
