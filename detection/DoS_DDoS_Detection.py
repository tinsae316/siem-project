import asyncio
import datetime
from collections import defaultdict, deque
from psycopg.types.json import Json
from collector.db import init_db
import ipaddress
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("firewall-flood-detector")

CONFIG = {
    "threshold": 1000,            # number of denied requests
    "window_seconds": 60,         # detection window
    "alert_dedupe_seconds": 300,  # suppress duplicate alerts for 5 minutes
    "db_batch_size": 20,
    "whitelist_src_cidrs": ["10.0.0.0/8", "192.168.0.0/16"]
}

# ---------- Helpers ----------
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

# ---------- Detector ----------
class FirewallFloodDetector:
    def __init__(self):
        # track blocked attempts { src_ip: deque[timestamps] }
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
            if event_type != "firewall" or outcome not in ["denied", "blocked"]:
                continue

            dq = self.blocked_attempts[src_ip]
            dq.append(ts)

            # expire old requests
            while dq and (ts - dq[0]).total_seconds() > CONFIG["window_seconds"]:
                dq.popleft()

            # threshold check
            if len(dq) >= CONFIG["threshold"]:
                alert_id = f"firewall_flood|{src_ip}"
                last_alert = self.last_alert_time.get(alert_id)

                if last_alert and (ts - last_alert).total_seconds() < CONFIG["alert_dedupe_seconds"]:
                    continue  # dedup

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
                dq.clear()  # reset to avoid spamming
        return alerts

# ---------- Fetch logs ----------
async def fetch_firewall_logs(pool, limit=10000):
    logs = []
    try:
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute("""
                    SELECT timestamp, source_ip, destination_ip, category, outcome, raw
                    FROM logs
                    WHERE 'firewall' = ANY(category)
                    ORDER BY timestamp DESC
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

# ---------- Insert alerts ----------
async def insert_alerts(pool, alerts):
    if not alerts:
        return
    insert_sql = """
    INSERT INTO alerts (
        timestamp, rule, source_ip,
        attempt_count, severity, technique, raw, score, evidence
    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    ON CONFLICT (timestamp, rule, source_ip)
    DO UPDATE SET
        attempt_count = alerts.attempt_count + EXCLUDED.attempt_count,
        raw = EXCLUDED.raw
    """
    params_list = []
    for alert in alerts:
        ts_val = ensure_dt(alert["@timestamp"])
        params_list.append((
            ts_val,
            alert["rule"],
            alert["source.ip"],
            alert["count"],
            alert["severity"],
            alert["attack.technique"],
            Json(alert),
            alert["score"],
            alert["evidence"]
        ))

    try:
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                batch_size = CONFIG["db_batch_size"]
                for i in range(0, len(params_list), batch_size):
                    await cur.executemany(insert_sql, params_list[i:i+batch_size])
        logger.info(f"Saved {len(alerts)} alerts to DB")
    except Exception as e:
        logger.exception("[!] Error inserting alerts into DB")

# ---------- Main ----------
async def main():
    pool = await init_db()
    logs = await fetch_firewall_logs(pool)
    detector = FirewallFloodDetector()
    alerts = detector.detect(logs)
    if alerts:
        await insert_alerts(pool, alerts)
        for a in alerts:
            logger.warning("[ALERT] %s - Source:%s Count:%s Severity:%s",
                           a["rule"], a["source.ip"], a["count"], a["severity"])
    else:
        logger.info("No firewall flood detected.")

if __name__ == "__main__":
    asyncio.run(main())
