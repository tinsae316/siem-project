# detection/Hard_Endpoint_Scan_Detection.py
import asyncio
import datetime
from collections import defaultdict
from psycopg.types.json import Json
import os
from dotenv import load_dotenv
from collector.db import init_db  # your existing DB init function

load_dotenv()

# --- Fetch logs from DB ---
async def fetch_web_logs(pool):
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute("""
                SELECT timestamp, username, source_ip, url_path
                FROM logs
                WHERE 'web' = ANY(category)
                ORDER BY timestamp ASC
            """)
            rows = await cur.fetchall()
            logs = []
            for r in rows:
                logs.append({
                    "@timestamp": r[0],
                    "user": {"name": r[1]},
                    "source_ip": r[2],
                    "url_path": r[3]
                })
            return logs

# --- Detection function ---
def detect_hard_endpoint_scanning(logs, threshold=5, window_minutes=5):
    alerts = []
    ip_counter = defaultdict(list)

    sensitive_endpoints = ["/admin", "/login", "/config", "/backup",
                           "/setup", "/db", "/phpmyadmin"]  # extend as needed

    for log in logs:
        ip = str(log.get("source_ip") or log.get("source", {}).get("ip"))
        ts_raw = log.get("@timestamp")
        ts = ts_raw if isinstance(ts_raw, datetime.datetime) else datetime.datetime.fromisoformat(str(ts_raw))

        path = str(log.get("url_path") or "").lower()
        if any(se in path for se in sensitive_endpoints):
            ip_counter[ip].append((ts, path))
            # Keep only recent hits within time window
            recent_hits = [(t, p) for t, p in ip_counter[ip] if (ts - t).total_seconds() <= window_minutes * 60]
            ip_counter[ip] = recent_hits

            # Alert if threshold exceeded
            unique_paths = {p for _, p in recent_hits}
            if len(unique_paths) >= threshold:
                alerts.append({
                    "rule": "Hard Endpoint Scanning",
                    "source.ip": ip,
                    "@timestamp": ts.isoformat(),
                    "count": len(recent_hits),
                    "severity": "HIGH",
                    "attack.technique": "endpoint_scanning",
                    "paths": list(unique_paths)
                })
    return alerts

# --- Insert alert into DB ---
async def insert_alert_into_db(pool, alert: dict):
    insert_sql = """
    INSERT INTO alerts (
        timestamp, rule, user_name, source_ip,
        attempt_count, severity, technique, raw
    ) VALUES (
        %(timestamp)s, %(rule)s, %(user_name)s, %(source_ip)s,
        %(attempt_count)s, %(severity)s, %(technique)s, %(raw)s
    )
    """
    ts_val = datetime.datetime.fromisoformat(alert.get("@timestamp"))
    src_ip = str(alert.get("source.ip"))

    raw_copy = {k: (str(v) if "ip" in k or k == "paths" else v) for k, v in alert.items()}

    params = {
        "timestamp": ts_val,
        "rule": alert.get("rule"),
        "user_name": None,
        "source_ip": src_ip,
        "attempt_count": alert.get("count"),
        "severity": alert.get("severity"),
        "technique": alert.get("attack.technique"),
        "raw": Json(raw_copy)
    }

    try:
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(insert_sql, params)
        print(f"[*] Alert saved: {alert.get('rule')} - {src_ip}")
    except Exception as e:
        print(f"[!] Error inserting alert into DB: {e}")
        print("Alert data:", alert)

# --- Main execution ---
async def main():
    pool = await init_db()
    logs = await fetch_web_logs(pool)
    alerts = detect_hard_endpoint_scanning(logs)

    if alerts:
        for alert in alerts:
            await insert_alert_into_db(pool, alert)
            print(f"[ALERT] {alert['rule']} - IP:{alert['source.ip']} "
                  f"Time:{alert['@timestamp']} Severity:{alert['severity']} Paths:{alert['paths']}")
    else:
        print("[*] No advanced endpoint scanning detected.")

if __name__ == "__main__":
    asyncio.run(main())
