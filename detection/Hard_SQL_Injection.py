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

# --- CONFIGURATION (Added alert_dedupe_seconds) ---
CONFIG = {
    "rate_threshold": 3,
    "window_minutes": 5,
    "alert_dedupe_seconds": 300, # 5 minutes
}

# --- GLOBAL DEDUPLICATION STATE ---
LAST_ALERT_TIME = {}

# --- SQLi detection function (Updated for Deduplication) ---
def detect_sqli(logs, rate_threshold=CONFIG["rate_threshold"], window_minutes=CONFIG["window_minutes"]):
    alerts = []
    ip_counter = defaultdict(list)
    sqli_regex = re.compile(r"(?i)(' OR '1'='1|union select|--|'; drop|or 1=1)")
    dedupe_window_sec = CONFIG["alert_dedupe_seconds"]

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
                ip_counter[ip] = recent_attempts # Keep state clean

                if len(recent_attempts) >= rate_threshold:
                    
                    # --- Deduplication Check ---
                    alert_id = f"SQLi|{ip}"
                    last_alert_ts = LAST_ALERT_TIME.get(alert_id)
                    
                    # Check: Skip alert creation if a recent alert already exists for this IP
                    if last_alert_ts and (ts - last_alert_ts).total_seconds() < dedupe_window_sec:
                        continue
                    # --- End Deduplication Check ---
                    
                    severity = "HIGH"
                    if len(recent_attempts) >= rate_threshold:
                        severity = "CRITICAL"

                    # Only create and append the alert if the deduplication check passes
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
                    
                    # Update the last alert time
                    LAST_ALERT_TIME[alert_id] = ts
                    
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
    try:
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
    except Exception as e:
        print(f"[!] DB query failed: {e}")
    return logs

# --- Insert alert into DB (Updated with ON CONFLICT) ---
async def insert_alert(pool, alert: dict):
    # Added ON CONFLICT DO NOTHING to ensure database deduplication works
    insert_sql = """
    INSERT INTO alerts (
        timestamp, rule, user_name, source_ip,
        attempt_count, severity, technique, raw
    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    ON CONFLICT (timestamp, rule, source_ip) DO NOTHING;
    """
    try:
        ts_val = datetime.datetime.fromisoformat(alert["@timestamp"]) if isinstance(alert["@timestamp"], str) else alert["@timestamp"]
        src_ip = str(alert.get("source.ip")) if alert.get("source.ip") else None
        
        raw_copy = {}
        for k, v in alert.items():
            if k == "@timestamp":
                raw_copy[k] = ts_val.isoformat()
            elif isinstance(v, (datetime.datetime, datetime.date)):
                raw_copy[k] = v.isoformat()
            elif isinstance(v, IPv4Address):
                raw_copy[k] = str(v)
            else:
                raw_copy[k] = v
        
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
    await pool.open()  # ensure the async pool is open

    if args.full_scan:
        print(f"[{datetime.datetime.now(datetime.timezone.utc).isoformat()}] Starting FULL SQLi scan of all logs...")
        logs = await fetch_web_logs(pool, since=None)
        alerts = detect_sqli(logs)
        for alert in alerts:
            # Only alerts that passed the in-memory check are printed/sent to SSE
            print(f"[ALERT] {alert['rule']} - User:{alert['user.name']} IP:{alert['source.ip']} "
                  f"Attempts:{alert['count']} Severity:{alert['severity']}")
            await insert_alert(pool, alert)
        if not alerts:
            print("[*] No SQL Injection detected (full scan).")
        return

    # --- Continuous scheduled scan for recent logs ---
    while True:
        scan_time = datetime.datetime.now(datetime.timezone.utc)
        print(f"\n[{scan_time.isoformat()}] Starting scheduled SQLi scan for recent logs...")
        last_scan = get_last_scan_time()
        
        # Clear the LAST_ALERT_TIME state for the incremental scan to re-evaluate
        global LAST_ALERT_TIME
        LAST_ALERT_TIME = {}
        
        # Fetch a wider window of logs to ensure detection logic works correctly
        lookback_time = scan_time - datetime.timedelta(minutes=CONFIG["window_minutes"])
        
        try:
            logs = await fetch_web_logs(pool, since=lookback_time)
        except Exception as e:
            print(f"[!] Connection error, reopening pool: {e}")
            pool = await init_db()
            await pool.open()
            logs = await fetch_web_logs(pool, since=lookback_time)

        alerts = detect_sqli(logs)

        for alert in alerts:
            # Only alerts that passed the in-memory check are printed/sent to SSE
            print(f"[ALERT] {alert['rule']} - User:{alert['user.name']} IP:{alert['source.ip']} "
                  f"Attempts:{alert['count']} Severity:{alert['severity']}")
            await insert_alert(pool, alert)

        if not alerts:
            print(f"[{datetime.datetime.now(datetime.timezone.utc).isoformat()}] No SQL Injection detected.")
        else:
            print(f"[*] Completed scheduled scan. Generated {len(alerts)} non-deduplicated alerts.")

        set_last_scan_time(scan_time)
        await asyncio.sleep(30)

if __name__ == "__main__":
    asyncio.run(main()) 