# detection/Protocol_Misuse_Detector.py
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
logger = logging.getLogger("protocol-misuse-detector")

# ---------------- Configuration ----------------
CONFIG = {
    "unusual_protocols": ["icmp", "udp", "ftp", "telnet"],
    "attempt_threshold": 3,
    "window_minutes": 5,
    "alert_dedupe_seconds": 300,
    "db_batch_size": 20,
    "whitelist_src_cidrs": ["10.0.0.0/8", "192.168.0.0/16"]
}
LAST_SCAN_FILE = "last_scan_protocol.txt"

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
        # Fallback for logs that might include port
        if isinstance(ip_str, str) and ":" in ip_str:
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
class ProtocolMisuseDetector:
    def __init__(self):
        self.protocol_usage = defaultdict(lambda: defaultdict(deque))
        self.last_alert_time = {}

    def detect(self, logs):
        alerts = []
        window_sec = CONFIG["window_minutes"] * 60

        for log in logs:
            ts = ensure_dt(log.get("@timestamp"))
            src_ip = normalize_ip(log.get("source", {}).get("ip"))
            dst_ip = normalize_ip(log.get("destination", {}).get("ip"))
            protocol = (log.get("network", {}).get("transport") or "unknown").lower()
            event_type = log.get("event", {}).get("category", [])
            outcome = (log.get("event", {}).get("outcome") or "").lower()

            if not src_ip or is_whitelisted(src_ip):
                continue
            if "firewall" not in event_type:
                continue

            dq = self.protocol_usage[src_ip][protocol]
            dq.append(ts)
            
            # Sliding window logic
            while dq and (ts - dq[0]).total_seconds() > window_sec:
                dq.popleft()

            if len(dq) >= CONFIG["attempt_threshold"]:
                alert_id = f"protocol_misuse|{src_ip}|{protocol}"
                last_alert = self.last_alert_time.get(alert_id)
                if last_alert and (ts - last_alert).total_seconds() < CONFIG["alert_dedupe_seconds"]:
                    continue

                score = min(10.0, len(dq) / CONFIG["attempt_threshold"] * 5.0)
                alerts.append({
                    "rule": "Suspicious Protocol Misuse",
                    "source.ip": src_ip,
                    "destination.ip": dst_ip,
                    "@timestamp": ts.isoformat(),
                    "protocol": protocol,
                    "count": len(dq),
                    "severity": "HIGH" if score >= 5 else "MEDIUM",
                    "score": score,
                    "attack.technique": "protocol_misuse",
                    "evidence": f"{len(dq)} attempts using unusual protocol '{protocol}' in last {CONFIG['window_minutes']} minutes"
                })
                self.last_alert_time[alert_id] = ts
                # CRITICAL FIX: Removed dq.clear() to maintain rate-limiting state
                
        return alerts

# ---------------- Fetch Logs (Stubbed for completeness) ----------------
async def fetch_firewall_logs(pool, limit=5000, since=None):
    logs = []
    try:
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                if since:
                    await cur.execute("""
                        SELECT timestamp, username, source_ip, destination_ip, 
                               destination_port, protocol, category, message, raw
                        FROM logs
                        WHERE 'firewall' = ANY(category) AND timestamp > %s
                        ORDER BY timestamp ASC
                        LIMIT %s
                    """, (since, limit))
                else:
                    await cur.execute("""
                        SELECT timestamp, username, source_ip, destination_ip, 
                               destination_port, protocol, category, message, raw
                        FROM logs
                        WHERE 'firewall' = ANY(category)
                        ORDER BY timestamp ASC
                        LIMIT %s
                    """, (limit,))
                rows = await cur.fetchall()

        for r in rows:
            ts = r[0]
            raw = r[8] or {}
            logs.append({
                "@timestamp": ts,
                "user": {"name": r[1]},
                "source": {"ip": r[2]},
                "destination": {"ip": r[3], "port": r[4]},
                "network": {"transport": r[5]},
                "event": {"category": r[6]},
                "message": r[7],
                "raw": raw
            })
    except Exception as e:
        logger.error(f"[!] Error fetching logs: {e}")
    return logs

# ---------------- DB Insert ----------------
async def insert_alerts(pool, alerts):
    if not alerts:
        return

    insert_sql = """
    INSERT INTO alerts (
        timestamp, rule, user_name, source_ip,
        attempt_count, severity, technique, raw, score, evidence
    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    ON CONFLICT (timestamp, rule, source_ip) DO NOTHING
    """

    params_list = []
    for alert in alerts:
        ts_val = ensure_dt(alert["@timestamp"])
        src_ip = normalize_ip(alert["source.ip"])

        # Ensure raw object is JSON serializable
        raw_copy = {k: (str(v) if isinstance(v, (datetime.datetime, ipaddress.IPv4Address, ipaddress.IPv6Address)) else v)
                    for k, v in alert.items()}

        params_list.append((
            ts_val,
            alert["rule"],
            None,
            src_ip,
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
        
        # Print individual alert save confirmations
        for alert in alerts:
            src_ip = alert.get("source.ip")
            print(f"[*] Alert saved: {alert.get('rule')} - Src: {src_ip}")
        
        logger.info(f"Saved {len(alerts)} alerts to DB")
    except Exception as e:
        logger.exception("[!] Error inserting alerts into DB")
        for a in alerts:
            logger.debug("Alert data: %s", a)

# ---------------- Main ----------------
async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--full-scan", action="store_true", help="Scan all logs, not just new ones.")
    args = parser.parse_args()

    pool = await init_db()
    detector = ProtocolMisuseDetector()

    if args.full_scan:
        logger.info("Starting FULL protocol misuse scan...")
        logs = await fetch_firewall_logs(pool, limit=5000, since=None)
        alerts = detector.detect(logs)
        if alerts:
            for a in alerts:
                logger.warning("[ALERT] %s - IP:%s Protocol:%s Time:%s Severity:%s Count:%s",
                               a["rule"], a["source.ip"], a["protocol"], a["@timestamp"], a["severity"], a["count"])
            await insert_alerts(pool, alerts)
        else:
            logger.info("[*] No suspicious protocol misuse detected (full scan).")
        return

    while True:
        scan_time = datetime.datetime.now(datetime.timezone.utc)
        logger.info(f"[{scan_time.isoformat()}] Starting scheduled protocol misuse scan...")
        last_scan = get_last_scan_time()
        
        # Adjust fetch window to ensure state is maintained
        lookback_time = scan_time - datetime.timedelta(minutes=CONFIG["window_minutes"])
        
        # Clear the in-memory state for the incremental scan to re-evaluate (optional, but good practice for scheduled runs)
        detector.protocol_usage.clear()
        detector.last_alert_time.clear() 
        
        logs = await fetch_firewall_logs(pool, limit=5000, since=lookback_time)
        alerts = detector.detect(logs)

        if alerts:
            for a in alerts:
                logger.warning("[ALERT] %s - IP:%s Protocol:%s Time:%s Severity:%s Count:%s",
                               a["rule"], a["source.ip"], a["protocol"], a["@timestamp"], a["severity"], a["count"])
            await insert_alerts(pool, alerts)
        else:
            logger.info(f"[{datetime.datetime.now(datetime.timezone.utc).isoformat()}] No suspicious protocol misuse detected.")

        set_last_scan_time(scan_time)
        await asyncio.sleep(40)

if __name__ == "__main__":
    asyncio.run(main())