# detection/Hard_XSS_Detection.py
import asyncio
import datetime
import re
from collections import defaultdict
from psycopg.types.json import Json
from ipaddress import IPv4Address
import os
import sys

# ensure project root is importable (collector is sibling of detection/)
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from collector.db import init_db  # your existing DB init function

# --- Advanced XSS patterns ---
xss_patterns = [
    r"<script.*?>.*?</script>",
    r"javascript:",
    r"on\w+\s*=",
    r"<iframe.*?>",
    r"<img.*?on\w+\s*=.*?>",
    r"alert\s*\(.*?\)",
    r"document\.cookie",
]
xss_regex = re.compile("|".join(xss_patterns), re.IGNORECASE)

# --- Last-scan file ---
LAST_SCAN_FILE = "last_scan_xss.txt"

def get_last_scan_time():
    if os.path.exists(LAST_SCAN_FILE):
        with open(LAST_SCAN_FILE, "r") as f:
            return datetime.datetime.fromisoformat(f.read().strip())
    return None

def set_last_scan_time(ts):
    # ts should be timezone-aware UTC
    with open(LAST_SCAN_FILE, "w") as f:
        f.write(ts.isoformat())

# --- Fetch web logs (supports since filter) ---
async def fetch_web_logs(pool, since=None, limit=5000):
    logs = []
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            if since:
                await cur.execute("""
                    SELECT timestamp, username, source_ip, http_method, url_path, raw
                    FROM logs
                    WHERE 'web' = ANY(category) AND timestamp > %s
                    ORDER BY timestamp ASC
                    LIMIT %s
                """, (since, limit))
            else:
                await cur.execute("""
                    SELECT timestamp, username, source_ip, http_method, url_path, raw
                    FROM logs
                    WHERE 'web' = ANY(category)
                    ORDER BY timestamp ASC
                    LIMIT %s
                """, (limit,))
            rows = await cur.fetchall()
            for r in rows:
                ts = r[0]
                # Make ts timezone-aware if not already
                if isinstance(ts, str):
                    ts_val = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
                else:
                    ts_val = ts
                raw = r[5] or {}
                logs.append({
                    "@timestamp": ts_val.isoformat(),
                    "user": {"name": r[1] or "unknown"},
                    "source": {"ip": r[2]},
                    "http_method": r[3],
                    "url": r[4],
                    "raw": raw
                })
    return logs

# --- XSS detection ---
def detect_hard_xss(logs, rate_threshold=3, window_minutes=5):
    alerts = []
    ip_counter = defaultdict(list)

    for log in logs:
        # Convert timestamp if necessary
        ts = log.get("@timestamp")
        if isinstance(ts, str):
            ts_dt = datetime.datetime.fromisoformat(ts)
        else:
            ts_dt = ts

        url = str(log.get("url", "") or "")
        raw_data_obj = log.get("raw", {}) or {}
        # try to extract request body or other fields to scan
        body = ""
        try:
            body = str(raw_data_obj.get("http", {}).get("request", {}).get("body", "") or "")
        except Exception:
            # fallback to string representation
            body = str(raw_data_obj)

        combined_input = url + " " + body + " " + str(raw_data_obj)

        if xss_regex.search(combined_input):
            ip = log["source"].get("ip")
            if isinstance(ip, IPv4Address):
                ip = str(ip)

            # Track attempts per IP
            ip_counter[ip].append(ts_dt)
            recent_attempts = [t for t in ip_counter[ip] if (ts_dt - t).total_seconds() <= window_minutes * 60]

            severity = "HIGH"
            if len(recent_attempts) >= rate_threshold:
                severity = "CRITICAL"

            alerts.append({
                "rule": "Advanced XSS Detected",
                "user.name": log["user"].get("name", "unknown"),
                "source.ip": ip,
                "@timestamp": ts_dt.isoformat(),
                "severity": severity,
                "attack.technique": "XSS",
                "http_method": log.get("http_method"),
                "url": url,
                "raw": body,
                "count": len(recent_attempts)
            })
    return alerts

async def insert_alert_into_db(pool, alert):
    insert_sql = """
    INSERT INTO alerts (
        timestamp, rule, user_name, source_ip,
        attempt_count, severity, technique, raw
    ) VALUES (
        %(timestamp)s, %(rule)s, %(user_name)s, %(source_ip)s,
        %(attempt_count)s, %(severity)s, %(technique)s, %(raw)s
    )
    ON CONFLICT (timestamp, rule, source_ip) DO NOTHING;
    """

    ts = alert.get("@timestamp")
    if isinstance(ts, str):
        ts_val = datetime.datetime.fromisoformat(ts)
    else:
        ts_val = ts

    src_ip = alert.get("source.ip")
    if isinstance(src_ip, IPv4Address):
        src_ip = str(src_ip)

    raw_copy = {k: (str(v) if isinstance(v, (IPv4Address, datetime.datetime)) else v)
                for k, v in alert.items()}

    params = {
        "timestamp": ts_val,
        "rule": alert.get("rule"),
        "user_name": alert.get("user.name"),
        "source_ip": src_ip,
        "attempt_count": alert.get("count", 1),
        "severity": alert.get("severity"),
        "technique": alert.get("attack.technique"),
        "raw": Json(raw_copy)
    }

    try:
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(insert_sql, params)
        print(f"[*] Alert saved: {alert.get('rule')} - {alert.get('user.name')} @ {src_ip}")
    except Exception as e:
        print(f"[!] Error inserting alert into DB: {e}")
        print("Alert data:", alert)

# --- Main ---
async def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--full-scan", action="store_true", help="Scan all logs, not just new ones.")
    args = parser.parse_args()

    pool = await init_db()
    await asyncio.sleep(0)  # just to keep async context consistent

    if args.full_scan:
        now = datetime.datetime.now(datetime.timezone.utc)
        print(f"[{now.isoformat()}] Starting FULL XSS scan of all web logs...")
        logs = await fetch_web_logs(pool, since=None)
        alerts = detect_hard_xss(logs)
        if alerts:
            for alert in alerts:
                print(f"[ALERT] {alert['rule']} - User:{alert['user.name']} IP:{alert['source.ip']} "
                      f"Attempts:{alert['count']} Severity:{alert['severity']}")
                await insert_alert_into_db(pool, alert)
        else:
            print("[*] No advanced XSS detected (full scan).")
        return

    # Continuous scheduled scan
    while True:
        scan_time = datetime.datetime.now(datetime.timezone.utc)
        print(f"\n[{scan_time.isoformat()}] Starting scheduled XSS scan for recent logs...")
        last_scan = get_last_scan_time()
        logs = await fetch_web_logs(pool, since=last_scan)
        alerts = detect_hard_xss(logs)

        if alerts:
            for alert in alerts:
                print(f"[ALERT] {alert['rule']} - User:{alert['user.name']} IP:{alert['source.ip']} "
                      f"Attempts:{alert['count']} Severity:{alert['severity']}")
                await insert_alert_into_db(pool, alert)
        else:
            now_no = datetime.datetime.now(datetime.timezone.utc)
            print(f"[{now_no.isoformat()}] No advanced XSS detected.")

        # update last scan time and sleep
        set_last_scan_time(scan_time)
        await asyncio.sleep(400)  # sleep 20 seconds between scans

if __name__ == "__main__":
    asyncio.run(main())
