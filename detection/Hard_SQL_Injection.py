# detection/SQLi_detect.py
import asyncio
import datetime
import re
from collections import defaultdict
from psycopg.types.json import Json
from ipaddress import IPv4Address
from collector.db import init_db  # existing DB functions

# --- SQLi detection function ---
def detect_sqli(logs, rate_threshold=3, window_minutes=5):
    alerts = []
    ip_counter = defaultdict(list)

    # Regex patterns for SQLi (case-insensitive)
    sqli_regex = re.compile(r"(?i)(' OR '1'='1|union select|--|'; drop|or 1=1)")

    for log in logs:
        if "web" in log["event"]["category"]:
            url = str(log.get("url", {}).get("original", "")).lower()
            body = str(log.get("http", {}).get("request", {}).get("body", "")).lower()
            combined_input = url + " " + body

            if sqli_regex.search(combined_input):
                ip = log["source"]["ip"]
                ts = datetime.datetime.fromisoformat(log["@timestamp"]) if isinstance(log["@timestamp"], str) else log["@timestamp"]

                # Track number of SQLi attempts per IP
                ip_counter[ip].append(ts)
                recent_attempts = [t for t in ip_counter[ip] if (ts - t).total_seconds() <= window_minutes * 60]

                severity = "HIGH"
                if len(recent_attempts) >= rate_threshold:
                    severity = "CRITICAL"

                alerts.append({
                    "rule": "Suspicious Web Activity - SQLi",
                    "user.name": log["user"]["name"],
                    "source.ip": ip,
                    "@timestamp": ts.isoformat(),
                    "severity": severity,
                    "attack.technique": "SQLi",
                    "message": log["message"],
                    "http_method": log.get("http", {}).get("request", {}).get("method"),
                    "url": log.get("url", {}).get("original"),
                    "body": body
                })
    return alerts

# --- Fetch web logs from DB ---
async def fetch_web_logs(pool):
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute("""
                SELECT timestamp, username AS user_name, source_ip, outcome,
                       message, http_method, url_path, raw
                FROM logs
                WHERE 'web' = ANY(category)
                ORDER BY timestamp ASC
            """)
            rows = await cur.fetchall()
            logs = []
            for r in rows:
                raw_data = r[7] or {}
                body = raw_data.get("http", {}).get("request", {}).get("body", "")
                logs.append({
                    "@timestamp": r[0].isoformat(),
                    "user": {"name": r[1] or "unknown"},
                    "source": {"ip": r[2]},
                    "event": {"category": ["web"], "outcome": r[3]},
                    "message": r[4],
                    "http": {"request": {"method": r[5], "body": body}},
                    "url": {"original": r[6]}
                })
            return logs


# --- Insert alert into DB ---
async def insert_alert(pool, alert: dict):
    insert_sql = """
    INSERT INTO alerts (
        timestamp, rule, user_name, source_ip,
        attempt_count, severity, technique, raw
    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    """
    ts = alert.get("@timestamp")
    ts_val = datetime.datetime.fromisoformat(ts) if isinstance(ts, str) else ts

    src_ip = str(alert.get("source.ip")) if alert.get("source.ip") else None

    raw_copy = {k: (str(v) if isinstance(v, IPv4Address) else v) for k, v in alert.items()}

    params = (
        ts_val,
        alert.get("rule"),
        alert.get("user.name"),
        src_ip,
        alert.get("count", 1),  # default 1 attempt
        alert.get("severity"),
        alert.get("attack.technique"),
        Json(raw_copy)
    )

    try:
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(insert_sql, params)
        print(f"[*] Alert saved: {alert.get('rule')} - {alert.get('user.name')} @ {src_ip}")
    except Exception as e:
        print(f"[!] Error inserting alert into DB: {e}")
        print("Alert data:", alert)

# --- Main execution ---
async def main():
    pool = await init_db()
    logs = await fetch_web_logs(pool)
    alerts = detect_sqli(logs)

    if alerts:
        for alert in alerts:
            await insert_alert(pool, alert)
    else:
        print("[*] No SQL Injection detected.")

if __name__ == "__main__":
    asyncio.run(main())
