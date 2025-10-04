import asyncio
import datetime
from collections import defaultdict, deque
from psycopg.types.json import Json
from collector.db import init_db
import ipaddress
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("firewall-allowed-blocked-detector")

CONFIG = {
    "deny_threshold": 3,         # how many denies after being allowed
    "window_minutes": 5,          # detection window
    "alert_dedupe_seconds": 300,  # suppress duplicate alerts for same IP
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

# ---------- Detector ----------
class FirewallAllowedBlockedDetector:
    def __init__(self):
        # track last allowed timestamp for each source
        self.allowed_sources = {}
        # track denied attempts in window
        self.denied_attempts = defaultdict(deque)
        # dedupe
        self.last_alert_time = {}

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

            if outcome == "allowed":
                self.allowed_sources[src_ip] = ts

            elif outcome in ["denied", "blocked"]:
                if src_ip not in self.allowed_sources:
                    continue  # only care if IP was previously allowed

                dq = self.denied_attempts[src_ip]
                dq.append(ts)

                # expire old entries
                while dq and (ts - dq[0]).total_seconds() > window_sec:
                    dq.popleft()

                if len(dq) >= CONFIG["deny_threshold"]:
                    alert_id = f"allowed_blocked|{src_ip}"
                    last_alert = self.last_alert_time.get(alert_id)
                    if last_alert and (ts - last_alert).total_seconds() < CONFIG["alert_dedupe_seconds"]:
                        continue

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
                    dq.clear()

        return alerts

# ---------- Fetch logs ----------
async def fetch_firewall_logs(pool, limit=5000):
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
    detector = FirewallAllowedBlockedDetector()
    alerts = detector.detect(logs)
    if alerts:
        await insert_alerts(pool, alerts)
        for a in alerts:
            logger.warning("[ALERT] %s - Source:%s Count:%s Severity:%s",
                           a["rule"], a["source.ip"], a["count"], a["severity"])
    else:
        logger.info("No allowed→blocked anomalies detected.")

if __name__ == "__main__":
    asyncio.run(main())
