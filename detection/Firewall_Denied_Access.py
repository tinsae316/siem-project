# detection/Firewall_Denied_Detection.py
import asyncio
import datetime
from collections import defaultdict, deque
from psycopg.types.json import Json
from collector.db import init_db
import ipaddress
import logging
import argparse
import os
import warnings # <-- Added for warning filter

# Suppress the known psycopg_pool RuntimeWarning about pool opening
warnings.filterwarnings(
    "ignore", 
    message="opening the async pool AsyncConnectionPool in the constructor is deprecated and will not be supported anymore in a future release.",
    category=RuntimeWarning
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("firewall-denied-detector")

CONFIG = {
    "attempt_threshold": 5,
    "window_minutes": 5,
    "alert_dedupe_seconds": 300,
    "db_batch_size": 20,
    "whitelist_src_cidrs": ["10.0.0.0/8", "192.168.0.0/16"]
}

LAST_SCAN_FILE = "last_scan_firewall.txt"

# ----------------- Helpers -----------------
def ensure_dt(ts) -> datetime.datetime:
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

# ----------------- Detection -----------------
class FirewallDeniedDetector:
    def __init__(self):
        self.blocked_attempts = defaultdict(deque)  # key=src_ip -> deque of timestamps
        self.last_alert_time = {}  # dedup key -> last alert time

    def detect(self, logs):
        alerts = []
        for log in logs:
            ts = ensure_dt(log.get("@timestamp"))
            user = log.get("user", {}).get("name", "unknown")
            src_ip = normalize_ip(log.get("source", {}).get("ip"))
            dst_ip = normalize_ip(log.get("destination", {}).get("ip"))
            dst_port = log.get("destination", {}).get("port")
            protocol = log.get("network", {}).get("transport", "unknown")

            if not src_ip or is_whitelisted(src_ip):
                continue

            event_type = log.get("event", {}).get("category")
            outcome = log.get("event", {}).get("outcome", "").lower()

            if event_type != "firewall" or outcome not in ["denied", "blocked"]:
                continue

            dq = self.blocked_attempts[src_ip]
            dq.append(ts)

            # Remove old attempts outside window
            window_sec = CONFIG["window_minutes"] * 60
            while dq and (ts - dq[0]).total_seconds() > window_sec:
                dq.popleft()

            if len(dq) >= CONFIG["attempt_threshold"]:
                alert_id = f"firewall_denied|{src_ip}|{dst_ip}"
                last_alert = self.last_alert_time.get(alert_id)
                
                # --- CHANGE START: Deduplicate at the generation point ---
                if last_alert and (ts - last_alert).total_seconds() < CONFIG["alert_dedupe_seconds"]:
                    # Skip alert generation if it's a duplicate based on the time window
                    continue 
                # --- CHANGE END ---
                
                score = min(10, len(dq) / CONFIG["attempt_threshold"] * 5)
                alerts.append({
                    "rule": "Firewall Denied Access",
                    "user.name": user,
                    "source.ip": src_ip,
                    "destination.ip": dst_ip,
                    "destination.port": dst_port,
                    "protocol": protocol,
                    "@timestamp": ts.isoformat(),
                    "count": len(dq),
                    "severity": "HIGH" if score >= 5 else "MEDIUM",
                    "score": score,
                    "attack.technique": "network_denial",
                    "evidence": f"{len(dq)} denied attempts in last {CONFIG['window_minutes']} minutes"
                })
                self.last_alert_time[alert_id] = ts
        return alerts

# ----------------- Fetch logs -----------------
async def fetch_firewall_logs(pool, limit=5000, since=None):
    logs = []
    try:
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                if since:
                    await cur.execute("""
                        SELECT timestamp, username, source_ip, destination_ip, destination_port,
                               category, outcome, raw, network
                        FROM logs
                        WHERE 'firewall' = ANY(category) AND timestamp > %s
                        ORDER BY timestamp ASC
                        LIMIT %s
                    """, (since, limit))
                else:
                    await cur.execute("""
                        SELECT timestamp, username, source_ip, destination_ip, destination_port,
                               category, outcome, raw, network
                        FROM logs
                        WHERE 'firewall' = ANY(category)
                        ORDER BY timestamp ASC
                        LIMIT %s
                    """, (limit,))
                rows = await cur.fetchall()

        for r in rows:
            raw = r[7] or {}
            network = r[8] or {}
            logs.append({
                "@timestamp": r[0],
                "user": {"name": r[1]},
                "source": {"ip": r[2]},
                "destination": {"ip": r[3], "port": r[4]},
                "event": {"category": r[5][0] if isinstance(r[5], list) else r[5], "outcome": r[6]},
                "raw": raw,
                "network": network
            })
    except Exception as e:
        logger.exception(f"[!] Error fetching logs: {e}")
    return logs

# ----------------- Insert alerts -----------------
async def insert_alerts(pool, alerts):
    if not alerts:
        return
    insert_sql = """
    INSERT INTO alerts (
        timestamp, rule, user_name, source_ip,
        attempt_count, severity, technique, raw, score, evidence
    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    ON CONFLICT (timestamp, rule, source_ip) DO NOTHING;
    """
    params_list = []
    for alert in alerts:
        ts_val = ensure_dt(alert["@timestamp"])
        params_list.append((
            ts_val,
            alert["rule"],
            alert.get("user.name"),
            alert.get("source.ip"),
            alert.get("count", 1),
            alert.get("severity"),
            alert.get("attack.technique"),
            Json(alert),
            alert.get("score"),
            alert.get("evidence")
        ))
    try:
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                batch_size = CONFIG["db_batch_size"]
                for i in range(0, len(params_list), batch_size):
                    await cur.executemany(insert_sql, params_list[i:i+batch_size])
        
        # Print individual alert save confirmations
        for alert in alerts:
            src_ip = alert.get("source.ip")
            print(f"[*] Alert saved: {alert.get('rule')} - Src: {src_ip}")
        
        logger.info(f"✅ Saved {len(alerts)} new alerts to DB (duplicates skipped).")
    except Exception as e:
        logger.exception("[!] Error inserting alerts into DB")
        for a in alerts:
            logger.debug("Alert data: %s", a)

# ----------------- Main Runner -----------------
async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--full-scan", action="store_true", help="Scan all logs, not just new ones.")
    args = parser.parse_args()

    pool = await init_db()
    detector = FirewallDeniedDetector()

    if args.full_scan:
        logger.info("Starting FULL scan of all firewall logs...")
        logs = await fetch_firewall_logs(pool, limit=5000, since=None)
        alerts = detector.detect(logs)
        if alerts:
            await insert_alerts(pool, alerts)
            # The logger.warning calls here now only print non-deduplicated alerts
            for a in alerts:
                logger.warning("[ALERT] %s - IP:%s User:%s Time:%s Count:%s Severity:%s",
                               a["rule"], a["source.ip"], a["user.name"],
                               a["@timestamp"], a["count"], a["severity"])
        else:
            logger.info("No denied firewall activity detected (full scan).")
        return

    # --- Scheduled incremental scans ---
    while True:
        scan_time = datetime.datetime.now(datetime.timezone.utc)
        logger.info(f"Starting scheduled scan for recent firewall logs at {scan_time.isoformat()}...")
        last_scan = get_last_scan_time()
        logs = await fetch_firewall_logs(pool, limit=5000, since=last_scan)
        alerts = detector.detect(logs)
        if alerts:
            await insert_alerts(pool, alerts)
            for a in alerts:
                logger.warning("[ALERT] %s - IP:%s User:%s Time:%s Count:%s Severity:%s",
                               a["rule"], a["source.ip"], a["user.name"],
                               a["@timestamp"], a["count"], a["severity"])
        else:
            logger.info("No denied firewall activity detected.")

        set_last_scan_time(scan_time)
        await asyncio.sleep(40)

if __name__ == "__main__":
    asyncio.run(main())