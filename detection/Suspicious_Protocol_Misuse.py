import asyncio
import datetime
from collections import defaultdict, deque
from psycopg.types.json import Json
from collector.db import init_db
import ipaddress
import logging
import math

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("protocol-misuse-detector")

CONFIG = {
    "unusual_protocols": ["icmp", "udp", "ftp", "telnet"],
    "attempt_threshold": 3,
    "window_minutes": 5,
    "alert_dedupe_seconds": 300,
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
    if hasattr(ip_str, 'compressed'):
        ip_str = str(ip_str)
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

# ---------- Detector ----------
class ProtocolMisuseDetector:
    def __init__(self):
        # { src_ip: { protocol: deque[timestamps] } }
        self.protocol_usage = defaultdict(lambda: defaultdict(deque))
        # dedup { alert_id: last_alert_time }
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

            #if event_type != "firewall" or protocol not in CONFIG["unusual_protocols"]:
            if "firewall" not in event_type:
                continue

            dq = self.protocol_usage[src_ip][protocol]
            dq.append(ts)

            # expire old events
            while dq and (ts - dq[0]).total_seconds() > window_sec:
                dq.popleft()

            # threshold check
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
                dq.clear()  # avoid immediate repeat

        return alerts

# ---------- Fetch logs ----------
async def fetch_firewall_logs(pool, limit=5000):
    logs = []
    try:
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute("""
                    SELECT timestamp, source_ip, destination_ip, network, category, outcome, raw
                    FROM logs
                    WHERE 'firewall' = ANY(category)
                    ORDER BY timestamp DESC
                    LIMIT %s
                """, (limit,))
                rows = await cur.fetchall()
        for r in rows:
            raw = r[6] or {}
            network = r[3] or {}
            logs.append({
                "@timestamp": r[0],
                "source": {"ip": r[1]},
                "destination": {"ip": r[2]},
                "network": network,
                "event": {"category": r[4], "outcome": r[5]},
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
            None,
            alert["source.ip"],
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
    detector = ProtocolMisuseDetector()
    alerts = detector.detect(logs)

    if alerts:
        await insert_alerts(pool, alerts)
        for a in alerts:
            logger.warning("[ALERT] %s - IP:%s Protocol:%s Time:%s Severity:%s Count:%s",
                           a["rule"], a["source.ip"], a["protocol"],
                           a["@timestamp"], a["severity"], a["count"])
    else:
        logger.info("No suspicious protocol misuse detected.")

if __name__ == "__main__":
    asyncio.run(main())
