# detection/Hard_Endpoint_Scan_Detection.py
import asyncio
import datetime
from collections import defaultdict
from psycopg.types.json import Json
from collector.db import init_db
import os
from dotenv import load_dotenv
import argparse

load_dotenv()

LAST_SCAN_FILE = "last_scan_endpoint.txt"

# ---------------- Helpers ----------------
def ensure_dt(ts):
    if isinstance(ts, datetime.datetime):
        return ts if ts.tzinfo else ts.replace(tzinfo=datetime.timezone.utc)
    if isinstance(ts, str):
        try:
            return datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except Exception:
            return datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)
    return datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)

def get_last_scan_time():
    if os.path.exists(LAST_SCAN_FILE):
        with open(LAST_SCAN_FILE, "r") as f:
            return datetime.datetime.fromisoformat(f.read().strip())
    return None

def set_last_scan_time(ts):
    with open(LAST_SCAN_FILE, "w") as f:
        f.write(ts.isoformat())

# ---------------- Fetch logs ----------------
async def fetch_web_logs(pool, limit=5000, since=None):
    logs = []
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            if since:
                await cur.execute("""
                    SELECT timestamp, username, source_ip, url_path
                    FROM logs
                    WHERE 'web' = ANY(category) AND timestamp > %s
                    ORDER BY timestamp ASC
                    LIMIT %s
                """, (since, limit))
            else:
                await cur.execute("""
                    SELECT timestamp, username, source_ip, url_path
                    FROM logs
                    WHERE 'web' = ANY(category)
                    ORDER BY timestamp ASC
                    LIMIT %s
                """, (limit,))
            rows = await cur.fetchall()
            for r in rows:
                logs.append({
                    "@timestamp": r[0],
                    "user": {"name": r[1]},
                    "source_ip": r[2],
                    "url_path": r[3]
                })
    return logs

# ---------------- Detection ----------------
def detect_hard_endpoint_scanning(logs, threshold=5, window_minutes=5):
    alerts = []
    ip_counter = defaultdict(list)
    sensitive_endpoints = ["/admin", "/login", "/config", "/backup",
                           "/setup", "/db", "/phpmyadmin"]

    for log in logs:
        ip = str(log.get("source_ip") or log.get("source", {}).get("ip"))
        ts_raw = log.get("@timestamp")
        ts = ensure_dt(ts_raw)
        path = str(log.get("url_path") or "").lower()
        if any(se in path for se in sensitive_endpoints):
            ip_counter[ip].append((ts, path))
            # keep only recent hits within window
            recent_hits = [(t, p) for t, p in ip_counter[ip] if (ts - t).total_seconds() <= window_minutes*60]
            ip_counter[ip] = recent_hits

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

# ---------------- Insert alerts ----------------
async def insert_alert_into_db(pool, alert: dict):
    insert_sql = """
    INSERT INTO alerts (
        timestamp, rule, user_name, source_ip,
        attempt_count, severity, technique, raw
    )
    VALUES (
        %(timestamp)s, %(rule)s, %(user_name)s, %(source_ip)s,
        %(attempt_count)s, %(severity)s, %(technique)s, %(raw)s
    )
    ON CONFLICT (timestamp, rule, source_ip) DO NOTHING;
    """

    ts_val = ensure_dt(alert.get("@timestamp"))
    src_ip = str(alert.get("source.ip"))
    # Serialize safely: convert any non-JSON-safe values
    raw_copy = {k: (str(v) if k in ("paths", "source.ip") else v) for k, v in alert.items()}

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


# ---------------- Main runner ----------------
async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--full-scan", action="store_true", help="Scan all logs, not just new ones.")
    args = parser.parse_args()

    pool = await init_db()

    if args.full_scan:
        print("[*] Starting FULL scan of all web logs...")
        logs = await fetch_web_logs(pool, limit=5000, since=None)
        alerts = detect_hard_endpoint_scanning(logs)
        if alerts:
            for alert in alerts:
                await insert_alert_into_db(pool, alert)
                print(f"[ALERT] {alert['rule']} - IP:{alert['source.ip']} "
                      f"Time:{alert['@timestamp']} Severity:{alert['severity']} Paths:{alert['paths']}")
        else:
            print("[*] No advanced endpoint scanning detected (full scan).")
        return

    # Scheduled incremental scan
    detector_window = 5
    while True:
        scan_time = datetime.datetime.now(datetime.timezone.utc)
        last_scan = get_last_scan_time()
        print(f"[*] Scheduled scan starting at {scan_time.isoformat()}...")
        logs = await fetch_web_logs(pool, limit=5000, since=last_scan)
        alerts = detect_hard_endpoint_scanning(logs)
        if alerts:
            for alert in alerts:
                await insert_alert_into_db(pool, alert)
                print(f"[ALERT] {alert['rule']} - IP:{alert['source.ip']} "
                      f"Time:{alert['@timestamp']} Severity:{alert['severity']} Paths:{alert['paths']}")
        else:
            print("[*] No advanced endpoint scanning detected.")

        set_last_scan_time(scan_time)
        await asyncio.sleep(40)

if __name__ == "__main__":
    asyncio.run(main())
