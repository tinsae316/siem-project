# detection/Hard_Bruteforce_Detection.py
import asyncio
import datetime
from collections import defaultdict
from psycopg.types.json import Json
import argparse
import os
import sys, os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))


# Use your existing init_db from collector (we are not editing collector/db.py)
from collector.db import init_db

# ---------------- Detection function (unchanged logic) ----------------
def detect_failed_logins(logs, threshold=5, window_minutes=5):
    alerts = []
    user_ip_attempts = defaultdict(list)  # (username, ip)
    ip_attempts = defaultdict(list)       # ip only
    user_attempts = defaultdict(list)     # username only

    for log in logs:
        if log.get("event", {}).get("category") == "authentication" and log.get("event", {}).get("outcome") == "failure":
            ts = log["@timestamp"]
            user = log.get("user", {}).get("name")
            ip = log.get("source", {}).get("ip")

            # Track attempts
            user_ip_attempts[(user, ip)].append(ts)
            ip_attempts[ip].append((ts, user))
            user_attempts[user].append((ts, ip))

            # Helper: filter sliding window
            def recent(attempts):
                return [t for t in attempts if (ts - t[0]).total_seconds() <= window_minutes * 60]

            # --- Rule 1: Brute force (same user+IP) ---
            r1 = [t for t in user_ip_attempts[(user, ip)] if (ts - t).total_seconds() <= window_minutes * 60]
            if len(r1) >= threshold:
                alerts.append({
                    "rule": "Brute Force (user+IP)",
                    "user.name": user,
                    "source.ip": ip,
                    "@timestamp": ts.isoformat() if isinstance(ts, datetime.datetime) else str(ts),
                    "count": len(r1),
                    "severity": "HIGH",
                    "attack.technique": "brute_force",
                })

            # --- Rule 2: Credential Stuffing (one IP, many accounts) ---
            r2 = recent(ip_attempts[ip])
            unique_users = {u for _, u in r2}
            if len(r2) >= threshold and len(unique_users) >= 3:
                alerts.append({
                    "rule": "Credential Stuffing",
                    "user.name": "Multiple",
                    "source.ip": ip,
                    "@timestamp": ts.isoformat() if isinstance(ts, datetime.datetime) else str(ts),
                    "count": len(r2),
                    "severity": "CRITICAL",
                    "attack.technique": "credential_stuffing",
                })

            # --- Rule 3: Account Targeted Brute Force (one account, many IPs) ---
            r3 = recent(user_attempts[user])
            unique_ips = {i for _, i in r3}
            if len(r3) >= threshold and len(unique_ips) >= 3:
                alerts.append({
                    "rule": "Account Targeted Brute Force",
                    "user.name": user,
                    "source.ip": "Multiple",
                    "@timestamp": ts.isoformat() if isinstance(ts, datetime.datetime) else str(ts),
                    "count": len(r3),
                    "severity": "HIGH",
                    "attack.technique": "distributed_bruteforce",
                })

    return alerts

# ------------------ DB helpers inside this file (no changes to collector) ------------------

async def ensure_alerts_table(pool):
    """Create alerts table if it doesn't exist (we're doing this here so collector/db.py remains untouched)."""
    create_sql = """
    CREATE TABLE IF NOT EXISTS alerts (
        id SERIAL PRIMARY KEY,
        timestamp TIMESTAMPTZ NOT NULL,
        rule TEXT NOT NULL,
        username TEXT,
        source_ip INET,
        count INT,
        severity TEXT,
        attack_technique TEXT,
        raw JSONB
    )
    """
    try:
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(create_sql)
    except Exception as e:
        print(f"[!] Error creating alerts table: {e}")
        raise

async def insert_alert_into_db(pool, alert: dict):
    """
    Insert one alert record into alerts table with correct column names.
    Converts IP to string and stores full alert JSON.
    """
    insert_sql = """
    INSERT INTO alerts (
        timestamp, rule, user_name, source_ip,
        attempt_count, severity, technique, raw
    ) VALUES (
        %(timestamp)s, %(rule)s, %(user_name)s, %(source_ip)s,
        %(attempt_count)s, %(severity)s, %(technique)s, %(raw)s
    )
    """
    # Normalize timestamp
    ts = alert.get("@timestamp")
    if isinstance(ts, str):
        try:
            ts_val = datetime.datetime.fromisoformat(ts)
        except Exception:
            ts_val = ts
    else:
        ts_val = ts

    # Convert IP to string
    src_ip = str(alert.get("source.ip")) if alert.get("source.ip") else None

    # Prepare JSON-safe raw copy (convert any IPs to strings)
    raw_copy = {k: (str(v) if "ip" in k else v) for k, v in alert.items()}

    params = {
        "timestamp": ts_val,
        "rule": alert.get("rule"),
        "user_name": alert.get("user.name"),
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
        print(f"[*] Alert saved: {alert.get('rule')} - {alert.get('user.name')} @ {src_ip}")
    except Exception as e:
        print(f"[!] Error inserting alert into DB: {e}")
        print("Alert data:", alert)

# ------------------ Fetch logs from logs table (same logic you used earlier) ------------------

LAST_SCAN_FILE = "last_scan_bf.txt"

def get_last_scan_time():
    if os.path.exists(LAST_SCAN_FILE):
        with open(LAST_SCAN_FILE, "r") as f:
            return datetime.datetime.fromisoformat(f.read().strip())
    return None

def set_last_scan_time(ts):
    with open(LAST_SCAN_FILE, "w") as f:
        f.write(ts.isoformat())

async def fetch_logs(pool, limit=5000, since=None):
    logs = []
    try:
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                if since:
                    await cur.execute(
                        """
                        SELECT timestamp, source_ip, username, outcome, category, message, raw
                        FROM logs
                        WHERE timestamp > %s
                        ORDER BY timestamp ASC
                        LIMIT %s
                        """,
                        (since, limit)
                    )
                else:
                    await cur.execute(
                        """
                        SELECT timestamp, source_ip, username, outcome, category, message, raw
                        FROM logs
                        ORDER BY timestamp ASC
                        LIMIT %s
                        """,
                        (limit,)
                    )
                rows = await cur.fetchall()

        for row in rows:
            # row[0] is timestamp (TIMESTAMPTZ -> datetime)
            # row[1] source_ip, row[2] username, row[3] outcome, row[4] category (TEXT[]), row[5] message, row[6] raw json
            category_val = None
            try:
                if row[4]:
                    # If category is stored as TEXT[], pick first string or entire list depending on your usage
                    category_val = row[4][0] if isinstance(row[4], (list, tuple)) and len(row[4]) > 0 else row[4]
            except Exception:
                category_val = None

            logs.append({
                "@timestamp": row[0],
                "source": {"ip": row[1]},
                "user": {"name": row[2]},
                "event": {
                    "outcome": row[3],
                    "category": category_val
                },
                "message": row[5],
                "raw": row[6],
            })
    except Exception as e:
        print(f"[!] Error fetching logs: {e}")
    return logs

# ------------------ Main runner ------------------

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--full-scan", action="store_true", help="Scan all logs, not just new ones.")
    args = parser.parse_args()

    pool = await init_db()  # uses collector/db.py's init_db (unchanged)
    await ensure_alerts_table(pool)

    if args.full_scan:
        print(f"[{datetime.datetime.now(datetime.timezone.utc).isoformat()}] Starting FULL scan of all logs...")
        logs = await fetch_logs(pool, limit=5000, since=None)
        alerts = detect_failed_logins(logs)
        if alerts:
            for a in alerts:
                print(f"[ALERT] {a['rule']} - User:{a['user.name']} IP:{a['source.ip']} "
                      f"Attempts:{a['count']} Time:{a['@timestamp']} Severity:{a['severity']}\n")
                await insert_alert_into_db(pool, a)
        else:
            print("No suspicious activity detected (full scan).")
        return  # exit after full scan

    # --- Continuous scheduled recent log scanning ---
    while True:
        scan_time = datetime.datetime.now(datetime.timezone.utc)
        print(f"\n[{scan_time.isoformat()}] Starting scheduled scan for recent logs...")
        last_scan = get_last_scan_time()
        logs = await fetch_logs(pool, limit=5000, since=last_scan)
        alerts = detect_failed_logins(logs)

        if alerts:
            for a in alerts:
                print(f"[ALERT] {a['rule']} - User:{a['user.name']} IP:{a['source.ip']} "
                      f"Attempts:{a['count']} Time:{a['@timestamp']} Severity:{a['severity']}\n")
                await insert_alert_into_db(pool, a)
        else:
            print(f"[{datetime.datetime.now(datetime.timezone.utc).isoformat()}] No suspicious activity detected.")

        # update last scan time
        set_last_scan_time(scan_time)

        # wait 20 seconds before next scan
        await asyncio.sleep(40)

if __name__ == "__main__":
    asyncio.run(main())
