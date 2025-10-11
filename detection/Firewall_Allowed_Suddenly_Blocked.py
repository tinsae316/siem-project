# detection/Firewall_Allowed_Blocked_Detection.py
import asyncio
import datetime
from collections import defaultdict, deque
from psycopg.types.json import Json
from collector.db import init_db
import ipaddress
import logging
import argparse
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("firewall-allowed-blocked-detector")

CONFIG = {
    "deny_threshold": 3,           # how many denies after being allowed
    "window_minutes": 5,           # detection window
    "alert_dedupe_seconds": 300,   # suppress duplicate alerts for same IP
    "db_batch_size": 20,
    "whitelist_src_cidrs": ["10.0.0.0/8", "192.168.0.0/16"]
}

LAST_SCAN_FILE = "last_scan_allowed_blocked.txt"

# ----------------- Helpers -----------------
def ensure_dt(ts):
    if isinstance(ts, datetime.datetime):
        return ts if ts.tzinfo else ts.replace(tzinfo=datetime.timezone.utc)
    if isinstance(ts, str):
        try:
            return datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except Exception:
            return datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)
    return datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)

def normalize_ip(ip_str):
    if not ip_str:
        return None
    try:
        return str(ipaddress.ip_address(ip_str))
    except Exception:
        if ":" in ip_str and ip_str.count(":") == 1:
            return ip_str.split(":")[0]
        return ip_str

def is_whitelisted(ip: str) -> bool:
    if not ip:
        return False
    try:
        ip_obj = ipaddress.ip_address(ip)
        for cidr in CONFIG["whitelist_src_cidrs"]:
            if ip_obj in ipaddress.ip_network(cidr):
                return True
    except Exception:
        return False
    return False

def get_last_scan_time():
    if os.path.exists(LAST_SCAN_FILE):
        with open(LAST_SCAN_FILE, "r") as f:
            return datetime.datetime.fromisoformat(f.read().strip())
    return None

def set_last_scan_time(ts):
    with open(LAST_SCAN_FILE, "w") as f:
        f.write(ts.isoformat())

# ----------------- Detector -----------------
class FirewallAllowedBlockedDetector:
    def __init__(self):
        # State for detection logic
        self.allowed_sources = {}          # last allowed timestamp per source
        self.denied_attempts = defaultdict(deque)  # denied attempts per source
        # State for alert deduplication
        self.last_alert_time = {}          # dedupe alerts

    def detect(self, logs):
        alerts = []
        window_sec = CONFIG["window_minutes"] * 60

        for log in logs:
            ts = ensure_dt(log.get("@timestamp"))
            src_ip = normalize_ip(log.get("source", {}).get("ip"))
            dst_ip = normalize_ip(log.get("destination", {}).get("ip"))
            outcome = (log.get("event", {}).get("outcome") or "").lower()
            category = log.get("event", {}).get("category", "")

            if not src_ip or is_whitelisted(src_ip):
                continue
            if isinstance(category, list):
                category = category[0] if category else ""
            if category != "firewall":
                continue

            # Step 1: Track allowed events (state required for step 2)
            if outcome == "allowed":
                self.allowed_sources[src_ip] = ts

            # Step 2: Check for denied events following an allowed event
            elif outcome in ["denied", "blocked"]:
                
                # Check 1: Must have a prior 'allowed' event
                if src_ip not in self.allowed_sources:
                    continue

                dq = self.denied_attempts[src_ip]
                dq.append(ts)

                # Sliding window logic
                while dq and (ts - dq[0]).total_seconds() > window_sec:
                    dq.popleft()

                # Check 2: Must meet the rate threshold
                if len(dq) >= CONFIG["deny_threshold"]:
                    alert_id = f"allowed_blocked|{src_ip}"
                    last_alert = self.last_alert_time.get(alert_id)
                    
                    # Deduplication check
                    if last_alert and (ts - last_alert).total_seconds() < CONFIG["alert_dedupe_seconds"]:
                        continue

                    # Alert generation
                    alerts.append({
                        "rule": "Firewall Allowed → Suddenly Blocked",
                        "source.ip": src_ip,
                        "destination.ip": dst_ip,
                        "@timestamp": ts.isoformat(),
                        "count": len(dq),
                        "severity": "HIGH",
                        "score": min(10, len(dq) / CONFIG["deny_threshold"] * 7),
                        "attack.technique": "suspicious_behavior",
                        "evidence": f"Source {src_ip} was previously allowed but had {len(dq)} denied attempts in {CONFIG['window_minutes']} minutes"
                    })
                    self.last_alert_time[alert_id] = ts
                    # CRITICAL FIX: Removed dq.clear() to maintain rate-limiting state
                    # The sliding window logic handles state expiration, no need to clear on alert.

        return alerts

# ----------------- Fetch logs -----------------
async def fetch_firewall_logs(pool, limit=5000, since=None):
    logs = []
    try:
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                if since:
                    await cur.execute("""
                        SELECT timestamp, source_ip, destination_ip, category, outcome, raw
                        FROM logs
                        WHERE 'firewall' = ANY(category) AND timestamp > %s
                        ORDER BY timestamp ASC
                        LIMIT %s
                    """, (since, limit))
                else:
                    await cur.execute("""
                        SELECT timestamp, source_ip, destination_ip, category, outcome, raw
                        FROM logs
                        WHERE 'firewall' = ANY(category)
                        ORDER BY timestamp ASC
                        LIMIT %s
                    """, (limit,))
                rows = await cur.fetchall()

        for r in rows:
            raw = r[5] or {}
            logs.append({
                "@timestamp": r[0],
                "source": {"ip": r[1]},
                "destination": {"ip": r[2]},
                "event": {"category": r[3], "outcome": r[4]},
                "raw": raw
            })
    except Exception as e:
        logger.exception(f"[!] Error fetching logs: {e}")
    return logs

# ----------------- Insert alerts -----------------
async def insert_alerts(pool, alerts):
    if not alerts:
        return
    # ON CONFLICT is correct here for database-level deduplication
    insert_sql = """
    INSERT INTO alerts (
        timestamp, rule, source_ip,
        attempt_count, severity, technique, raw, score, evidence
    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    ON CONFLICT (timestamp, rule, source_ip) DO NOTHING;
    """
    params_list = []
    for alert in alerts:
        ts_val = ensure_dt(alert["@timestamp"])
        
        # Ensure raw object is JSON serializable
        raw_copy = {k: (str(v) if isinstance(v, (datetime.datetime, ipaddress.IPv4Address, ipaddress.IPv6Address)) else v)
                    for k, v in alert.items()}
        
        params_list.append((
            ts_val,
            alert["rule"],
            alert["source.ip"],
            alert.get("count", 1),
            alert.get("severity"),
            alert.get("attack.technique"),
            Json(raw_copy),
            alert.get("score"),
            alert.get("evidence")
        ))

    try:
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                batch_size = CONFIG["db_batch_size"]
                for i in range(0, len(params_list), batch_size):
                    await cur.executemany(insert_sql, params_list[i:i+batch_size])
        logger.info(f"✅ Saved {len(alerts)} new alerts to DB (duplicates skipped).")
    except Exception as e:
        logger.exception("[!] Error inserting alerts into DB")
        for a in alerts:
            logger.debug("Alert data: %s", a)


# ----------------- Main -----------------
async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--full-scan", action="store_true", help="Scan all logs, not just new ones.")
    args = parser.parse_args()

    pool = await init_db()
    detector = FirewallAllowedBlockedDetector()

    if args.full_scan:
        logger.info("Starting FULL scan of all firewall logs...")
        logs = await fetch_firewall_logs(pool, limit=5000, since=None)
        alerts = detector.detect(logs)
        if alerts:
            await insert_alerts(pool, alerts)
            for a in alerts:
                logger.warning("[ALERT] %s - Source:%s Count:%s Severity:%s",
                               a["rule"], a["source.ip"], a["count"], a["severity"])
        else:
            logger.info("No allowed→blocked anomalies detected (full scan).")
        return

    # --- Scheduled incremental scans ---
    while True:
        scan_time = datetime.datetime.now(datetime.timezone.utc)
        logger.info(f"Starting scheduled scan for recent firewall logs at {scan_time.isoformat()}...")
        
        # FIX: Fetch logs for the full time window to maintain accurate rate state
        lookback_time = scan_time - datetime.timedelta(minutes=CONFIG["window_minutes"])
        
        # FIX: Re-initialize the detector state for each scan to avoid processing old data multiple times
        # Only the dedupe state is kept across scans.
        detector.allowed_sources.clear()
        detector.denied_attempts.clear()
        
        logs = await fetch_firewall_logs(pool, limit=5000, since=lookback_time)
        alerts = detector.detect(logs)
        
        if alerts:
            await insert_alerts(pool, alerts)
            for a in alerts:
                logger.warning("[ALERT] %s - Source:%s Count:%s Severity:%s",
                               a["rule"], a["source.ip"], a["count"], a["severity"])
            logger.info(f"Generated {len(alerts)} non-deduplicated alerts.")
        else:
            logger.info("No allowed→blocked anomalies detected.")

        set_last_scan_time(scan_time)
        await asyncio.sleep(40)

if __name__ == "__main__":
    asyncio.run(main())