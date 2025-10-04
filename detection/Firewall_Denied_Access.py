import asyncio
import datetime
from collections import defaultdict, deque
from psycopg.types.json import Json
from collector.db import init_db  # reuse existing DB init
import ipaddress
import math
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("firewall-denied-detector")

CONFIG = {
    "attempt_threshold": 5,
    "window_minutes": 5,
    "alert_dedupe_seconds": 300,
    "db_batch_size": 20,
    "whitelist_src_cidrs": ["10.0.0.0/8", "192.168.0.0/16"]
}

# ---------- Helpers ----------
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
    if hasattr(ip_str, 'compressed'):
        ip_str = str(ip_str)
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return str(ip_obj)
    except Exception:
        # fallback: strip port if present
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

# ---------- Detection ----------
class FirewallDeniedDetector:
    def __init__(self):
        # key=src_ip -> deque of timestamps
        self.blocked_attempts = defaultdict(deque)
        # alert deduplication key -> last alert time
        self.last_alert_time = {}

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

            # record timestamp
            self.blocked_attempts[src_ip].append(ts)

            # expire old attempts
            window_sec = CONFIG["window_minutes"] * 60
            dq = self.blocked_attempts[src_ip]
            while dq and (ts - dq[0]).total_seconds() > window_sec:
                dq.popleft()

            # check threshold
            if len(dq) >= CONFIG["attempt_threshold"]:
                alert_id = f"firewall_denied|{src_ip}|{dst_ip}"
                last_alert = self.last_alert_time.get(alert_id)
                if last_alert and (ts - last_alert).total_seconds() < CONFIG["alert_dedupe_seconds"]:
                    continue  # dedup
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

# ---------- Fetch logs ----------
async def fetch_firewall_logs(pool, limit=5000):
    logs = []
    try:
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute("""
                    SELECT timestamp, username, source_ip, destination_ip, destination_port,
                           category, outcome, raw, network
                    FROM logs
                    WHERE 'firewall' = ANY(category)
                    ORDER BY timestamp DESC
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

# ---------- Insert alerts (batched) ----------
async def insert_alerts(pool, alerts):
    if not alerts:
        return
    insert_sql = """
    INSERT INTO alerts (
        timestamp, rule, user_name, source_ip,
        attempt_count, severity, technique, raw, score, evidence
    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
        logger.info(f"Saved {len(alerts)} alerts to DB")
    except Exception as e:
        logger.exception("[!] Error inserting alerts into DB")
        for a in alerts:
            logger.debug("Alert data: %s", a)

# ---------- Main Runner ----------
async def main():
    pool = await init_db()
    logs = await fetch_firewall_logs(pool)
    detector = FirewallDeniedDetector()
    alerts = detector.detect(logs)
    if alerts:
        await insert_alerts(pool, alerts)
        for a in alerts:
            logger.warning("[ALERT] %s - IP:%s User:%s Time:%s Count:%s Severity:%s",
                           a["rule"], a["source.ip"], a["user.name"],
                           a["@timestamp"], a["count"], a["severity"])
    else:
        logger.info("No denied firewall activity detected.")

if __name__ == "__main__":
    asyncio.run(main())
