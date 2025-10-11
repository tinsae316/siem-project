import asyncio
import datetime
import os
from collections import defaultdict, deque
from psycopg.types.json import Json
import ipaddress
import logging
import argparse
import sys

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from collector.db import init_db

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("firewall-flood-detector")

# ---------------- Configuration ----------------
CONFIG = {
    "threshold": 1000,            # number of denied requests
    "window_seconds": 60,         # detection window
    "alert_dedupe_seconds": 300,  # suppress duplicate alerts
    "db_batch_size": 20,
    "whitelist_src_cidrs": ["10.0.0.0/8", "192.168.0.0/16"]
}
LAST_SCAN_FILE = "last_scan_dos.txt"

# ---------------- Utility ----------------
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
        ip_obj = ipaddress.ip_address(ip_str)
        return str(ip_obj)
    except Exception:
        if ":" in ip_str and ip_str.count(":") == 1:
            return ip_str.split(":")[0]
        return ip_str

def is_whitelisted(ip: str):
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

# ---------------- Detector ----------------
class FirewallFloodDetector:
    def __init__(self):
        self.blocked_attempts = defaultdict(deque)
        self.last_alert_time = {}

    def detect(self, logs):
        alerts = []
        for log in logs:
            ts = ensure_dt(log.get("@timestamp"))
            src_ip = normalize_ip(log.get("source", {}).get("ip"))
            dst_ip = normalize_ip(log.get("destination", {}).get("ip"))
            outcome = (log.get("event", {}).get("outcome") or "").lower()
            event_type = log.get("event", {}).get("category")

            if not src_ip or is_whitelisted(src_ip):
                continue
            
            # Ensure event_type is checked correctly (as list in DB, or string in log)
            if isinstance(event_type, list):
                if "firewall" not in event_type:
                    continue
            elif event_type != "firewall":
                continue
            
            if outcome not in ["denied", "blocked"]:
                continue

            dq = self.blocked_attempts[src_ip]
            dq.append(ts)
            
            # Sliding window logic
            while dq and (ts - dq[0]).total_seconds() > CONFIG["window_seconds"]:
                dq.popleft()

            if len(dq) >= CONFIG["threshold"]:
                alert_id = f"firewall_flood|{src_ip}"
                last_alert = self.last_alert_time.get(alert_id)
                
                # Deduplication check
                if last_alert and (ts - last_alert).total_seconds() < CONFIG["alert_dedupe_seconds"]:
                    continue

                alerts.append({
                    "rule": "Firewall Flood Detection (Possible DoS/DDoS)",
                    "source.ip": src_ip,
                    "destination.ip": dst_ip,
                    "@timestamp": ts.isoformat(),
                    "count": len(dq),
                    "severity": "CRITICAL",
                    "score": 10.0,
                    "attack.technique": "denial_of_service",
                    "evidence": f"{len(dq)} denied requests in {CONFIG['window_seconds']} seconds"
                })
                self.last_alert_time[alert_id] = ts
        return alerts

# ---------------- DB ----------------
async def fetch_firewall_logs(pool, limit=10000, since=None):
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
            logs.append({
                "@timestamp": r[0],
                "source": {"ip": r[1]},
                "destination": {"ip": r[2]},
                "event": {"category": r[3], "outcome": r[4]},
                "raw": r[5] or {}
            })
    except Exception as e:
        logger.exception(f"[!] Error fetching logs: {e}")
    return logs

async def insert_alerts(pool, alerts):
    if not alerts:
        return
    # FIX: Added 'user_name' to the INSERT columns list.
    insert_sql = """
    INSERT INTO alerts (
        timestamp, rule, user_name, source_ip,
        attempt_count, severity, technique, raw
    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    ON CONFLICT (timestamp, rule, source_ip) DO NOTHING;
    """
    params_list = []
    for alert in alerts:
        ts_val = ensure_dt(alert["@timestamp"])
        
        # Ensure raw object is JSON serializable
        raw_copy = {k: (str(v) if isinstance(v, (datetime.datetime, ipaddress.IPv4Address, ipaddress.IPv6Address)) else v)
                    for k, v in alert.items()}
        
        # FIX: Added 'None' for the user_name column
        params_list.append((
            ts_val,
            alert["rule"],
            None,  # <-- Added value for user_name column
            alert["source.ip"],
            alert["count"],
            alert["severity"],
            alert["attack.technique"],
            Json(raw_copy),
        ))

    try:
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                batch_size = CONFIG["db_batch_size"]
                # The executemany call must now match the 8 placeholders in insert_sql
                for i in range(0, len(params_list), batch_size):
                    await cur.executemany(insert_sql, params_list[i:i+batch_size])
        logger.info(f"✅ Saved {len(alerts)} alerts to DB (duplicates skipped).")
    except Exception as e:
        logger.exception("[!] Error inserting alerts into DB")

# ---------------- Main ----------------
async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--full-scan", action="store_true", help="Scan all logs, not just new ones.")
    args = parser.parse_args()

    pool = await init_db()
    detector = FirewallFloodDetector()

    if args.full_scan:
        logger.info("Starting FULL DoS/DDoS scan...")
        logs = await fetch_firewall_logs(pool, limit=10000, since=None)
        alerts = detector.detect(logs)
        if alerts:
            for a in alerts:
                logger.warning("[ALERT] %s - Source:%s Count:%s Severity:%s",
                               a["rule"], a["source.ip"], a["count"], a["severity"])
            await insert_alerts(pool, alerts)
        else:
            logger.info("No DoS/DDoS detected (full scan).")
        return

    while True:
        scan_time = datetime.datetime.now(datetime.timezone.utc)
        logger.info(f"[{scan_time.isoformat()}] Starting scheduled DoS/DDoS scan...")
        
        # Fetch logs for the full time window to maintain accurate rate state
        lookback_time = scan_time - datetime.timedelta(seconds=CONFIG["window_seconds"])
        
        # Clear rate state for the incremental scan to avoid accumulating irrelevant past data
        detector.blocked_attempts.clear()
        
        logs = await fetch_firewall_logs(pool, limit=10000, since=lookback_time)
        alerts = detector.detect(logs)

        if alerts:
            for a in alerts:
                logger.warning("[ALERT] %s - Source:%s Count:%s Severity:%s",
                               a["rule"], a["source.ip"], a["count"], a["severity"])
            await insert_alerts(pool, alerts)
        else:
            logger.info(f"[{datetime.datetime.now(datetime.timezone.utc).isoformat()}] No firewall flood detected.")

        set_last_scan_time(scan_time)
        await asyncio.sleep(40)

if __name__ == "__main__":
    asyncio.run(main())