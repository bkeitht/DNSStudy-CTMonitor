"""ct-stream-filter — Certstream firehose consumer with Aho-Corasick matching.

Connects to certstream-server-go WebSocket, matches SANs against ct_watchlist
patterns loaded from PostgreSQL, and writes matched alerts directly to the
ct_alerts table via asyncpg (bypasses API rate limiter and N+1 pattern loading).

Health is reported to the DNSStudy API stream-state endpoint at low frequency.
"""

import asyncio
import json
import logging
import os
import signal
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

import asyncpg
import httpx
import websockets
from ahocorasick_rs import AhoCorasick

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CERTSTREAM_WS_URL = os.environ.get("CERTSTREAM_WS_URL", "ws://certstream:8080/")
POSTGRES_DSN = os.environ.get(
    "POSTGRES_DSN",
    "postgresql://{user}:{password}@{host}:{port}/{db}".format(
        user=quote(os.environ.get("POSTGRES_USER", "dnsstudy"), safe=""),
        password=quote(os.environ.get("POSTGRES_PASSWORD", ""), safe=""),
        host=os.environ.get("POSTGRES_HOST", "dnsstudy-postgres"),
        port=os.environ.get("POSTGRES_PORT", "5432"),
        db=os.environ.get("POSTGRES_DB", "dnsstudy"),
    ),
)
DNSSTUDY_API_URL = os.environ.get("DNSSTUDY_API_URL", "http://dnsstudy-api:8000")
PATTERN_RELOAD_INTERVAL = int(os.environ.get("PATTERN_RELOAD_INTERVAL", "300"))
HEARTBEAT_INTERVAL = int(os.environ.get("HEARTBEAT_INTERVAL", "60"))

# WebSocket reconnect backoff
WS_BACKOFF_MIN = 1
WS_BACKOFF_MAX = 30
WS_PING_INTERVAL = 30

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("ct-stream-filter")

# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------

# Aho-Corasick automaton for typosquat patterns (fast multi-pattern match)
_automaton: Optional[AhoCorasick] = None
# Mapping: automaton pattern index → (group_id, pattern_text)
_automaton_map: List[Tuple[str, str]] = []

# Exact patterns: {lowercase_pattern: [(group_id, pattern_text)]}
_exact_patterns: Dict[str, List[Tuple[str, str]]] = {}

# Suffix patterns: [(lowercase_pattern, group_id, pattern_text)]
_suffix_patterns: List[Tuple[str, str, str]] = []

# Stats
_stats = {
    "certs_processed": 0,
    "matches_found": 0,
    "alerts_written": 0,
    "errors": 0,
    "patterns_loaded": 0,
    "ws_reconnects": 0,
}

# Shutdown event
_shutdown = asyncio.Event()

# Observation context (detected once at startup)
_vantage_country: Optional[str] = None
_vantage_asn: Optional[int] = None


# ---------------------------------------------------------------------------
# Pattern loading
# ---------------------------------------------------------------------------

async def load_patterns(pool: asyncpg.Pool) -> int:
    """Load active watchlist patterns from ct_watchlist table.

    Builds:
    - Aho-Corasick automaton from typosquat patterns (fast substring/exact match)
    - Dict of exact patterns keyed by lowercase pattern
    - List of suffix patterns for endswith matching
    """
    global _automaton, _automaton_map, _exact_patterns, _suffix_patterns

    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT group_id, pattern, pattern_type, source_domain "
            "FROM ct_watchlist WHERE is_active = true"
        )

    typosquat_patterns = []
    typosquat_map = []
    exact = {}
    suffix = []

    for row in rows:
        group_id = str(row["group_id"])
        pattern = row["pattern"]
        pattern_type = row["pattern_type"]
        pattern_lower = pattern.lower()

        if pattern_type == "typosquat":
            typosquat_patterns.append(pattern_lower)
            typosquat_map.append((group_id, pattern))
        elif pattern_type == "exact":
            exact.setdefault(pattern_lower, []).append((group_id, pattern))
        elif pattern_type == "suffix":
            suffix.append((pattern_lower, group_id, pattern))

    # Build Aho-Corasick automaton for typosquat patterns
    if typosquat_patterns:
        _automaton = AhoCorasick(typosquat_patterns)
    else:
        _automaton = None
    _automaton_map = typosquat_map
    _exact_patterns = exact
    _suffix_patterns = suffix

    total = len(typosquat_patterns) + sum(len(v) for v in exact.values()) + len(suffix)
    _stats["patterns_loaded"] = total

    logger.info(
        "Loaded %d patterns (%d exact, %d suffix, %d typosquat)",
        total,
        sum(len(v) for v in exact.values()),
        len(suffix),
        len(typosquat_patterns),
    )
    return total


async def pattern_reload_loop(pool: asyncpg.Pool) -> None:
    """Periodically reload patterns from the database."""
    while not _shutdown.is_set():
        try:
            await asyncio.wait_for(
                _shutdown.wait(), timeout=PATTERN_RELOAD_INTERVAL
            )
            break  # shutdown signaled
        except asyncio.TimeoutError:
            pass  # timeout = time to reload

        try:
            await load_patterns(pool)
        except Exception:
            logger.exception("Error reloading patterns")
            _stats["errors"] += 1


# ---------------------------------------------------------------------------
# Certificate matching
# ---------------------------------------------------------------------------

def match_certificate(
    all_domains: List[str],
) -> List[Dict[str, str]]:
    """Match SANs against loaded patterns.

    Returns list of {group_id, pattern, match_type} dicts.
    Only the first match per group_id is kept.
    """
    seen_groups: set = set()
    matches: List[Dict[str, str]] = []

    for domain in all_domains:
        domain_lower = domain.lower().strip()
        if not domain_lower:
            continue

        # 1. Typosquat matches via Aho-Corasick
        if _automaton is not None:
            for match_idx in _automaton.find_matches_as_indexes(domain_lower):
                # Aho-Corasick returns (pattern_index, start, end) tuples
                # ahocorasick-rs find_matches_as_indexes returns list of
                # (pattern_idx, start_pos, end_pos)
                if isinstance(match_idx, tuple):
                    pat_idx = match_idx[0]
                else:
                    pat_idx = match_idx
                group_id, pattern_text = _automaton_map[pat_idx]
                if group_id not in seen_groups:
                    # Typosquat: only match if the domain IS the pattern
                    # (not just contains it as substring)
                    if domain_lower == pattern_text.lower():
                        seen_groups.add(group_id)
                        matches.append({
                            "group_id": group_id,
                            "pattern": pattern_text,
                            "match_type": "typosquat",
                        })

        # 2. Exact matches
        if domain_lower in _exact_patterns:
            for group_id, pattern_text in _exact_patterns[domain_lower]:
                if group_id not in seen_groups:
                    seen_groups.add(group_id)
                    matches.append({
                        "group_id": group_id,
                        "pattern": pattern_text,
                        "match_type": "exact",
                    })

        # 3. Suffix matches
        for pat_lower, group_id, pattern_text in _suffix_patterns:
            if group_id not in seen_groups:
                if domain_lower == pat_lower or domain_lower.endswith("." + pat_lower):
                    seen_groups.add(group_id)
                    matches.append({
                        "group_id": group_id,
                        "pattern": pattern_text,
                        "match_type": "suffix",
                    })

    return matches


# ---------------------------------------------------------------------------
# Severity classification (mirrors ct_monitor_service.classify_severity)
# ---------------------------------------------------------------------------

def classify_severity(match_type: str, is_precert: bool) -> str:
    """Classify alert severity. Mirrors backend-api logic exactly."""
    base = {
        "typosquat": "HIGH",
        "exact": "MEDIUM",
        "suffix": "LOW",
    }.get(match_type, "INFO")

    if is_precert and base in ("HIGH", "MEDIUM"):
        base = {"HIGH": "MEDIUM", "MEDIUM": "LOW"}[base]

    return base


# ---------------------------------------------------------------------------
# Alert writing (direct PostgreSQL)
# ---------------------------------------------------------------------------

_INSERT_ALERT_SQL = """
INSERT INTO ct_alerts (
    id, group_id, detected_at, fingerprint_sha256, serial_number,
    subject_cn, san_entries, issuer_name, issuer_organization,
    not_before, not_after, is_precert, source,
    ct_log_name, ct_log_url, matched_pattern, match_type,
    severity, status, observation, extra_metadata,
    created_at, updated_at
) VALUES (
    $1, $2, $3, $4, $5,
    $6, $7, $8, $9,
    $10, $11, $12, $13,
    $14, $15, $16, $17,
    $18, $19, $20, $21,
    $22, $23
)
ON CONFLICT (group_id, fingerprint_sha256)
    WHERE fingerprint_sha256 IS NOT NULL AND fingerprint_sha256 != ''
DO NOTHING
"""


async def write_alerts(
    pool: asyncpg.Pool,
    matches: List[Dict[str, str]],
    cert_data: Dict[str, Any],
) -> int:
    """Write matched alerts directly to ct_alerts table.

    Returns number of alerts actually inserted (after dedup).
    """
    now = datetime.now(timezone.utc)
    fingerprint = (cert_data.get("fingerprint_sha256") or "").lower().replace(":", "")
    is_precert = cert_data.get("is_precert", False)

    observation = json.dumps({
        "source_type": "ct_log",
        "resolver_ip": None,
        "vantage_country": _vantage_country,
        "vantage_asn": _vantage_asn,
        "observed_at_utc": now.isoformat(),
    })

    inserted = 0
    async with pool.acquire() as conn:
        for m in matches:
            severity = classify_severity(m["match_type"], is_precert)
            try:
                result = await conn.execute(
                    _INSERT_ALERT_SQL,
                    uuid.uuid4(),                          # id
                    uuid.UUID(m["group_id"]),               # group_id
                    now,                                    # detected_at
                    fingerprint,                            # fingerprint_sha256
                    cert_data.get("serial_number"),         # serial_number
                    cert_data.get("subject_cn"),            # subject_cn
                    cert_data.get("san_entries", []),        # san_entries
                    cert_data.get("issuer_name"),            # issuer_name
                    cert_data.get("issuer_organization"),    # issuer_organization
                    cert_data.get("not_before"),             # not_before
                    cert_data.get("not_after"),              # not_after
                    is_precert,                             # is_precert
                    "certstream",                           # source
                    cert_data.get("ct_log_name"),            # ct_log_name
                    cert_data.get("ct_log_url"),             # ct_log_url
                    m["pattern"],                            # matched_pattern
                    m["match_type"],                         # match_type
                    severity,                               # severity
                    "new",                                  # status
                    observation,                            # observation (JSONB)
                    "{}",                                   # extra_metadata (JSONB)
                    now,                                    # created_at
                    now,                                    # updated_at
                )
                if result == "INSERT 0 1":
                    inserted += 1
            except Exception:
                logger.exception(
                    "Error writing alert for group %s pattern %s",
                    m["group_id"],
                    m["pattern"],
                )
                _stats["errors"] += 1

    return inserted


# ---------------------------------------------------------------------------
# Certstream message parsing
# ---------------------------------------------------------------------------

def parse_certstream_message(raw: str) -> Optional[Dict[str, Any]]:
    """Parse a certstream-server-go lite stream message.

    Expected format:
    {
        "message_type": "certificate_update",
        "data": {
            "update_type": "X509LogEntry" | "PrecertLogEntry",
            "leaf_cert": {
                "all_domains": ["example.com", "www.example.com"],
                "sha256": "AB:CD:...",
                "serial_number": "...",
                "subject": {"CN": "example.com", ...},
                "issuer": {"O": "Let's Encrypt", "aggregated": "...", ...},
                "not_before": 1234567890,
                "not_after": 1234567890,
            },
            "source": {"name": "...", "url": "..."}
        }
    }
    """
    try:
        msg = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None

    if msg.get("message_type") != "certificate_update":
        return None

    data = msg.get("data", {})
    leaf = data.get("leaf_cert", {})
    all_domains = leaf.get("all_domains", [])

    if not all_domains:
        return None

    # Parse epoch timestamps to datetime
    not_before = None
    not_after = None
    nb_raw = leaf.get("not_before")
    na_raw = leaf.get("not_after")
    if isinstance(nb_raw, (int, float)) and nb_raw > 0:
        not_before = datetime.fromtimestamp(nb_raw, tz=timezone.utc)
    if isinstance(na_raw, (int, float)) and na_raw > 0:
        not_after = datetime.fromtimestamp(na_raw, tz=timezone.utc)

    source_info = data.get("source", {})
    subject = leaf.get("subject", {})
    issuer = leaf.get("issuer", {})

    fingerprint = (leaf.get("sha256") or "").lower().replace(":", "")

    return {
        "all_domains": all_domains,
        "fingerprint_sha256": fingerprint,
        "serial_number": leaf.get("serial_number"),
        "subject_cn": subject.get("CN"),
        "issuer_name": issuer.get("aggregated"),
        "issuer_organization": issuer.get("O"),
        "not_before": not_before,
        "not_after": not_after,
        "is_precert": data.get("update_type") == "PrecertLogEntry",
        "san_entries": all_domains,
        "ct_log_name": source_info.get("name"),
        "ct_log_url": source_info.get("url"),
    }


# ---------------------------------------------------------------------------
# WebSocket consumer
# ---------------------------------------------------------------------------

async def consume_certstream(pool: asyncpg.Pool) -> None:
    """Connect to certstream WS and process certificate messages.

    Reconnects with exponential backoff on disconnection.
    """
    backoff = WS_BACKOFF_MIN

    while not _shutdown.is_set():
        try:
            logger.info("Connecting to %s", CERTSTREAM_WS_URL)
            async with websockets.connect(
                CERTSTREAM_WS_URL,
                ping_interval=WS_PING_INTERVAL,
                ping_timeout=WS_PING_INTERVAL,
                close_timeout=10,
                max_size=2**20,  # 1MB max message
            ) as ws:
                logger.info("Connected to %s", CERTSTREAM_WS_URL)
                backoff = WS_BACKOFF_MIN  # reset on successful connect

                async for raw in ws:
                    if _shutdown.is_set():
                        break

                    cert_data = parse_certstream_message(raw)
                    if cert_data is None:
                        continue

                    _stats["certs_processed"] += 1

                    # Match against patterns
                    matches = match_certificate(cert_data["all_domains"])
                    if matches:
                        _stats["matches_found"] += len(matches)
                        inserted = await write_alerts(pool, matches, cert_data)
                        _stats["alerts_written"] += inserted

                        if inserted > 0:
                            logger.info(
                                "Alert: %d inserts for %s (matches: %s)",
                                inserted,
                                cert_data.get("subject_cn", "?"),
                                ", ".join(
                                    f"{m['pattern']}({m['match_type']})"
                                    for m in matches
                                ),
                            )

        except asyncio.CancelledError:
            break
        except Exception:
            _stats["ws_reconnects"] += 1
            _stats["errors"] += 1
            logger.exception(
                "WebSocket error, reconnecting in %ds", backoff
            )
            try:
                await asyncio.wait_for(_shutdown.wait(), timeout=backoff)
                break  # shutdown during backoff
            except asyncio.TimeoutError:
                pass
            backoff = min(backoff * 2, WS_BACKOFF_MAX)


# ---------------------------------------------------------------------------
# Heartbeat
# ---------------------------------------------------------------------------

async def heartbeat_loop() -> None:
    """Report health to DNSStudy API stream-state endpoint."""
    url = f"{DNSSTUDY_API_URL}/api/v1/ct-monitor/stream-state"

    async with httpx.AsyncClient(timeout=10) as client:
        while not _shutdown.is_set():
            try:
                await asyncio.wait_for(
                    _shutdown.wait(), timeout=HEARTBEAT_INTERVAL
                )
                break
            except asyncio.TimeoutError:
                pass

            try:
                payload = {
                    "component": "sidecar",
                    "status": "running",
                    "certificates_processed": _stats["certs_processed"],
                    "errors_count": _stats["errors"],
                    "metadata": {
                        "matches_found": _stats["matches_found"],
                        "alerts_written": _stats["alerts_written"],
                        "patterns_loaded": _stats["patterns_loaded"],
                        "ws_reconnects": _stats["ws_reconnects"],
                    },
                }
                resp = await client.post(url, json=payload)
                if resp.status_code not in (200, 201):
                    logger.warning(
                        "Heartbeat POST returned %d: %s",
                        resp.status_code,
                        resp.text[:200],
                    )
            except Exception as e:
                logger.debug("Heartbeat failed: %s", e)


# ---------------------------------------------------------------------------
# Dedup index (optional — for ON CONFLICT to work, we need a unique index)
# ---------------------------------------------------------------------------

_DEDUP_INDEX_SQL = """
CREATE UNIQUE INDEX IF NOT EXISTS uq_ct_alerts_group_fingerprint
ON ct_alerts (group_id, fingerprint_sha256)
WHERE fingerprint_sha256 IS NOT NULL AND fingerprint_sha256 != ''
"""


async def ensure_dedup_index(pool: asyncpg.Pool) -> None:
    """Create the partial unique index for dedup if it doesn't exist."""
    try:
        async with pool.acquire() as conn:
            await conn.execute(_DEDUP_INDEX_SQL)
        logger.info("Dedup index verified/created")
    except Exception:
        logger.warning(
            "Could not create dedup index (may need manual creation)",
            exc_info=True,
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def run() -> None:
    """Main entry point — start all loops."""
    logger.info("ct-stream-filter starting")
    logger.info("Certstream WS: %s", CERTSTREAM_WS_URL)
    logger.info("Pattern reload interval: %ds", PATTERN_RELOAD_INTERVAL)
    logger.info("Heartbeat interval: %ds", HEARTBEAT_INTERVAL)

    # Connect to PostgreSQL
    try:
        pool = await asyncpg.create_pool(
            POSTGRES_DSN,
            min_size=2,
            max_size=5,
            command_timeout=30,
        )
    except Exception:
        logger.exception("Failed to connect to PostgreSQL")
        sys.exit(1)

    logger.info("Connected to PostgreSQL")

    # Ensure dedup index exists
    await ensure_dedup_index(pool)

    # Initial pattern load
    try:
        count = await load_patterns(pool)
        if count == 0:
            logger.warning("No active watchlist patterns found — will retry on reload")
    except Exception:
        logger.exception("Failed initial pattern load")
        _stats["errors"] += 1

    # Run all loops concurrently
    tasks = [
        asyncio.create_task(consume_certstream(pool), name="consumer"),
        asyncio.create_task(pattern_reload_loop(pool), name="pattern-reload"),
        asyncio.create_task(heartbeat_loop(), name="heartbeat"),
    ]

    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        pass
    finally:
        await pool.close()
        logger.info("ct-stream-filter stopped")


def _handle_signal(sig: signal.Signals) -> None:
    """Handle shutdown signals gracefully."""
    logger.info("Received %s, shutting down...", sig.name)
    _shutdown.set()


def main() -> None:
    loop = asyncio.new_event_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, _handle_signal, sig)
    try:
        loop.run_until_complete(run())
    finally:
        loop.close()


if __name__ == "__main__":
    main()
