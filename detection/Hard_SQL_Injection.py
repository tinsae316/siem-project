# detection/Hard_SQL_Injection.py
import asyncio
import datetime
import re
from collections import defaultdict
from psycopg.types.json import Json
from ipaddress import IPv4Address
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from collector.db import init_db  # existing DB functions

# --- SQLi detection function ---
def detect_sqli(logs, rate_threshold=3, window_minutes=5):
    alerts = []
    ip_counter = defaultdict(list)

    sqli_regex = re.compile(r"(?i)(' OR '1'='1|union select|--|'; drop|or 1=1)")

    for log in logs:
        if "web" in log["event"]["category"]:
            url = str(log.get("url", {}).get("original", "")).lower()
            body = str(log.get("http", {}).get("request", {}).get("body", "")).lower()
            combined_input = url + " " + body

            if sqli_regex.search(combined_input):
                ip = log["source"]["ip"]
                ts = datetime.datetime.fromisoformat(log["@timestamp"]) if isinstance(log["@timestamp"], str) else log["@timestamp"]

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
                    "body": body,
                    "count": len(recent_attempts)
                })
    return alerts

# --- Fetch web logs from DB ---
LAST_SCAN_FILE = "last_scan_sqli.txt"

def get_last_scan_time():
    if os.path.exists(LAST_SCAN_FILE):
        with open(LAST_SCAN_FILE, "r") as f:
            return datetime.datetime.fromisoformat(f.read().strip())
    return None

def set_last_scan_time(ts):
    with open(LAST_SCAN_FILE, "w") as f:
        f.write(ts.isoformat())

async def fetch_web_logs(pool, since=None):
    logs = []
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            if since:
                await cur.execute("""
                    SELECT timestamp, username AS user_name, source_ip, outcome,
                           message, http_method, url_path, raw
                    FROM logs
                    WHERE 'web' = ANY(category) AND timestamp > %s
                    ORDER BY timestamp ASC
                """, (since,))
            else:
                await cur.execute("""
                    SELECT timestamp, username AS user_name, source_ip, outcome,
                           message, http_method, url_path, raw
                    FROM logs
                    WHERE 'web' = ANY(category)
                    ORDER BY timestamp ASC
                """)
            rows = await cur.fetchall()
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
    ts_val = datetime.datetime.fromisoformat(alert["@timestamp"]) if isinstance(alert["@timestamp"], str) else alert["@timestamp"]
    src_ip = str(alert.get("source.ip")) if alert.get("source.ip") else None
    raw_copy = {k: (str(v) if isinstance(v, IPv4Address) else v) for k, v in alert.items()}

    params = (
        ts_val,
        alert.get("rule"),
        alert.get("user.name"),
        src_ip,
        alert.get("count", 1),
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
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--full-scan", action="store_true", help="Scan all logs, not just new ones.")
    args = parser.parse_args()

    pool = await init_db()

    if args.full_scan:
        print(f"[{datetime.datetime.now(datetime.timezone.utc).isoformat()}] Starting FULL SQLi scan of all logs...")
        logs = await fetch_web_logs(pool, since=None)
        alerts = detect_sqli(logs)
        if alerts:
            for alert in alerts:
                print(f"[ALERT] {alert['rule']} - User:{alert['user.name']} IP:{alert['source.ip']} "
                      f"Attempts:{alert['count']} Severity:{alert['severity']}")
                await insert_alert(pool, alert)
        else:
            print("[*] No SQL Injection detected (full scan).")
        return

    # --- Continuous scheduled scan for recent logs ---
    while True:
        scan_time = datetime.datetime.now(datetime.timezone.utc)
        print(f"\n[{scan_time.isoformat()}] Starting scheduled SQLi scan for recent logs...")
        last_scan = get_last_scan_time()
        logs = await fetch_web_logs(pool, since=last_scan)
        alerts = detect_sqli(logs)

        if alerts:
            for alert in alerts:
                print(f"[ALERT] {alert['rule']} - User:{alert['user.name']} IP:{alert['source.ip']} "
                      f"Attempts:{alert['count']} Severity:{alert['severity']}")
                await insert_alert(pool, alert)
        else:
            print(f"[{datetime.datetime.now(datetime.timezone.utc).isoformat()}] No SQL Injection detected.")

        set_last_scan_time(scan_time)
        await asyncio.sleep(40)

if __name__ == "__main__":
    asyncio.run(main())
