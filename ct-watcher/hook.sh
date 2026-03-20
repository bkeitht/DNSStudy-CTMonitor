#!/usr/bin/env bash
set -euo pipefail

# CertSpotter hook script — called for each certificate event.
#
# CertSpotter sets these bare env vars (no CERTSPOTTER_ prefix):
#   EVENT            — "discovered" or "watched"
#   CERT_SHA256      — hex SHA-256 fingerprint
#   SERIAL           — certificate serial number
#   ISSUER_DN        — full issuer DN string
#   SUBJECT_DN       — full subject DN string (may be empty)
#   NOT_BEFORE_RFC3339 — validity start
#   NOT_AFTER_RFC3339  — validity end
#   LOG_URI          — CT log URL
#   JSON_FILENAME    — path to JSON file with full cert details
#
# The JSON file contains a dns_names array with SANs.

DNSSTUDY_API_URL="${DNSSTUDY_API_URL:-http://dnsstudy-api:8000}"
INGEST_URL="${DNSSTUDY_API_URL}/api/v1/ct-monitor/ingest/certificate"

# Only process discovered events
if [ "${EVENT:-}" != "discovered" ]; then
    exit 0
fi

# Extract SANs from JSON file
san_entries="[]"
if [ -n "${JSON_FILENAME:-}" ] && [ -f "${JSON_FILENAME}" ]; then
    san_entries=$(jq -c '.dns_names // []' "${JSON_FILENAME}" 2>/dev/null || echo "[]")
fi

# Extract subject CN from SUBJECT_DN (format: "CN=example.com,O=...")
subject_cn=""
if [ -n "${SUBJECT_DN:-}" ]; then
    subject_cn=$(echo "${SUBJECT_DN}" | sed -n 's/.*CN=\([^,]*\).*/\1/p')
fi

# Extract issuer organization from ISSUER_DN (format: "...O=Let's Encrypt,...")
issuer_org=""
if [ -n "${ISSUER_DN:-}" ]; then
    issuer_org=$(echo "${ISSUER_DN}" | sed -n "s/.*O=\([^,]*\).*/\1/p")
fi

# Extract CT log name from LOG_URI (last path segment)
ct_log_name=""
if [ -n "${LOG_URI:-}" ]; then
    ct_log_name=$(echo "${LOG_URI}" | sed 's|.*/||; s|/$||')
fi

# Normalize fingerprint — strip colons, lowercase
fingerprint=""
if [ -n "${CERT_SHA256:-}" ]; then
    fingerprint=$(echo "${CERT_SHA256}" | tr -d ':' | tr '[:upper:]' '[:lower:]')
fi

# Parse timestamps (RFC3339 → ISO8601, which is what the API expects)
not_before="${NOT_BEFORE_RFC3339:-}"
not_after="${NOT_AFTER_RFC3339:-}"

# Build JSON payload matching CertificateEventSchema
payload=$(jq -n \
    --arg fingerprint "$fingerprint" \
    --arg serial "${SERIAL:-}" \
    --arg subject_cn "$subject_cn" \
    --argjson san_entries "$san_entries" \
    --arg issuer_name "${ISSUER_DN:-}" \
    --arg issuer_org "$issuer_org" \
    --arg not_before "$not_before" \
    --arg not_after "$not_after" \
    --arg ct_log_name "$ct_log_name" \
    --arg ct_log_url "${LOG_URI:-}" \
    '{
        fingerprint_sha256: $fingerprint,
        serial_number: $serial,
        subject_cn: (if $subject_cn == "" then null else $subject_cn end),
        san_entries: $san_entries,
        issuer_name: (if $issuer_name == "" then null else $issuer_name end),
        issuer_organization: (if $issuer_org == "" then null else $issuer_org end),
        not_before: (if $not_before == "" then null else $not_before end),
        not_after: (if $not_after == "" then null else $not_after end),
        is_precert: false,
        source: "certspotter",
        ct_log_name: (if $ct_log_name == "" then null else $ct_log_name end),
        ct_log_url: (if $ct_log_url == "" then null else $ct_log_url end)
    }')

# POST to ingest endpoint
http_code=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X POST "${INGEST_URL}" \
    -H "Content-Type: application/json" \
    -d "${payload}" 2>/dev/null) || true

if [ "${http_code}" = "202" ] || [ "${http_code}" = "200" ]; then
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) [INFO] Ingested cert ${fingerprint:0:16}... (${subject_cn:-unknown})"
else
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) [WARN] Ingest returned HTTP ${http_code:-error} for ${fingerprint:0:16}..." >&2
fi
