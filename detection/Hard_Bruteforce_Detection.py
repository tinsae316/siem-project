import asyncio
import datetime
from collections import defaultdict
from psycopg.types.json import Json
import argparse
import os
import sys
import ipaddress # <-- Import added for type checking

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

# Use your existing init_db from collector (we are not editing collector/db.py)
from collector.db import init_db

# --- CONFIGURATION (Added alert_dedupe_seconds) ---
CONFIG = {
    "attempt_threshold": 5,
    "window_minutes": 5,
    "alert_dedupe_seconds": 300, # 5 minutes
}

# --- GLOBAL DEDUPLICATION STATE (Simulates class state for the function) ---
LAST_ALERT_TIME = {}

# ------------------ Utility Function for Serialization FIX ------------------
def ensure_serializable(data):
    """Recursively converts non-JSON serializable objects (like datetime, ipaddress) to strings."""
    if isinstance(data, dict):
        return {k: ensure_serializable(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [ensure_serializable(item) for item in data]
    elif isinstance(data, (datetime.datetime, datetime.date)):
        return data.isoformat()
    # FIX: Convert ipaddress objects to string before serialization
    elif isinstance(data, (ipaddress.IPv4Address, ipaddress.IPv6Address, ipaddress.IPv4Network, ipaddress.IPv6Network)):
        return str(data)
    else:
        return data

# ------------------ Ensure alerts table exists ------------------
async def ensure_alerts_table(pool):
    create_table_sql = """
    CREATE TABLE IF NOT EXISTS alerts (
        id SERIAL PRIMARY KEY,
        timestamp TIMESTAMPTZ,
        rule TEXT,
        user_name TEXT,
        source_ip TEXT,
        attempt_count INT,
        severity TEXT,
        technique TEXT,
        raw JSONB,
        UNIQUE (timestamp, rule, source_ip)
    );
    """
    try:
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(create_table_sql)
        print("[*] 'alerts' table checked/created successfully.")
    except Exception as e:
        print(f"[!] Failed to create/check alerts table: {e}")

# ---------------- Detection function (No changes needed here for the JSON error) ----------------
def detect_failed_logins(logs, threshold=CONFIG["attempt_threshold"], window_minutes=CONFIG["window_minutes"]):
    alerts = []
    user_ip_attempts = defaultdict(list)
    ip_attempts = defaultdict(list)
    user_attempts = defaultdict(list)
    dedupe_window_sec = CONFIG["alert_dedupe_seconds"]

    for log in logs:
        if log.get("event", {}).get("category") == "authentication" and log.get("event", {}).get("outcome") == "failure":
            ts = log["@timestamp"]
            user = log.get("user", {}).get("name")
            ip = log.get("source", {}).get("ip")

            user_ip_attempts[(user, ip)].append(ts)
            ip_attempts[ip].append((ts, user))
            user_attempts[user].append((ts, ip))

            def recent(attempts):
                # Assumes attempts are tuples (ts, entity)
                return [t for t in attempts if (ts - t[0]).total_seconds() <= window_minutes * 60]

            def check_and_append_alert(rule, entity_key, details):
                alert_id = f"{rule}|{entity_key}"
                last_alert_ts = LAST_ALERT_TIME.get(alert_id)
                
                # Deduplication check: Only generate a NEW alert if enough time has passed
                if last_alert_ts and (ts - last_alert_ts).total_seconds() < dedupe_window_sec:
                    return

                alerts.append(details)
                LAST_ALERT_TIME[alert_id] = ts # Update the last alert time

            # Rule 1: Brute force (user+IP)
            r1 = [t for t in user_ip_attempts[(user, ip)] if (ts - t).total_seconds() <= window_minutes * 60]
            if len(r1) >= threshold:
                check_and_append_alert(
                    "Brute Force (user+IP)",
                    f"{user}|{ip}",
                    {
                        "rule": "Brute Force (user+IP)",
                        "user.name": user,
                        "source.ip": ip,
                        "@timestamp": ts.isoformat() if isinstance(ts, datetime.datetime) else str(ts),
                        "count": len(r1),
                        "severity": "HIGH",
                        "attack.technique": "brute_force",
                    }
                )

            # Rule 2: Credential Stuffing (one IP, many accounts)
            r2 = recent(ip_attempts[ip])
            unique_users = {u for _, u in r2}
            if len(r2) >= threshold and len(unique_users) >= 3:
                check_and_append_alert(
                    "Credential Stuffing",
                    ip,
                    {
                        "rule": "Credential Stuffing",
                        "user.name": "Multiple",
                        "source.ip": ip,
                        "@timestamp": ts.isoformat() if isinstance(ts, datetime.datetime) else str(ts),
                        "count": len(r2),
                        "severity": "CRITICAL",
                        "attack.technique": "credential_stuffing",
                    }
                )

            # Rule 3: Account Targeted Brute Force (one account, many IPs)
            r3 = recent(user_attempts[user])
            unique_ips = {i for _, i in r3}
            if len(r3) >= threshold and len(unique_ips) >= 3:
                check_and_append_alert(
                    "Account Targeted Brute Force",
                    user,
                    {
                        "rule": "Account Targeted Brute Force",
                        "user.name": user,
                        "source.ip": "Multiple",
                        "@timestamp": ts.isoformat() if isinstance(ts, datetime.datetime) else str(ts),
                        "count": len(r3),
                        "severity": "HIGH",
                        "attack.technique": "distributed_bruteforce",
                    }
                )

    return alerts

# ------------------ Insert alert into DB (FIXED) ------------------
async def insert_alert_into_db(pool, alert: dict):
    insert_sql = """
    INSERT INTO alerts (
        timestamp, rule, user_name, source_ip,
        attempt_count, severity, technique, raw
    ) VALUES (
        %(timestamp)s, %(rule)s, %(user_name)s, %(source_ip)s,
        %(attempt_count)s, %(severity)s, %(technique)s, %(raw)s
    )
    ON CONFLICT (timestamp, rule, source_ip) DO NOTHING
    """
    ts = alert.get("@timestamp")
    
    # Use timezone-aware datetime for PostgreSQL
    if isinstance(ts, str):
        try:
            ts_val = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
             ts_val = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)
    else:
        ts_val = ts if ts.tzinfo else ts.replace(tzinfo=datetime.timezone.utc)

    # FIX: Ensure 'source.ip' is converted to string for the SQL parameter
    src_ip_val = alert.get("source.ip")
    src_ip = str(src_ip_val) if src_ip_val else None
    
    # FIX: Use the utility function to ensure the entire raw dictionary is JSON serializable
    raw_serializable = ensure_serializable(alert)
    raw_serializable["@timestamp"] = ts_val.isoformat() # Use the proper datetime string

    params = {
        "timestamp": ts_val,
        "rule": alert.get("rule"),
        "user_name": alert.get("user.name"),
        "source_ip": src_ip, # SQL expects a string here
        "attempt_count": alert.get("count"),
        "severity": alert.get("severity"),
        "technique": alert.get("attack.technique"),
        "raw": Json(raw_serializable) # JSONB field with serializable data
    }

    try:
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(insert_sql, params)
        print(f"[*] Alert saved: {alert.get('rule')} - {alert.get('user.name')} @ {src_ip}")
    except Exception as e:
        print(f"[!] Error inserting alert into DB: {e}")
        print("Alert data:", alert) # Still print for debugging if other issues arise

# ------------------ Fetch logs ------------------
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
            category_val = None
            try:
                if row[4]:
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

## ------------------ Main runner ------------------
async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--full-scan", action="store_true", help="Scan all logs, not just new ones.")
    args = parser.parse_args()

    pool = await init_db()

    async with pool:
        await ensure_alerts_table(pool)

        if args.full_scan:
            print(f"[{datetime.datetime.now(datetime.timezone.utc).isoformat()}] Starting FULL scan of all logs...")
            
            # Fetch logs for full scan
            logs = await fetch_logs(pool, limit=5000, since=None)
            alerts = detect_failed_logins(logs)
            
            for a in alerts:
                # Print the alert (This is what goes to the SSE stream)
                print(f"[ALERT] {a['rule']} - User:{a['user.name']} IP:{str(a['source.ip'])} "
                      f"Attempts:{a['count']} Time:{a['@timestamp']} Severity:{a['severity']}")
                
                # Insert alert (Database ON CONFLICT will handle final deduplication)
                await insert_alert_into_db(pool, a)
            
            print(f"[*] Completed full scan. Generated {len(alerts)} non-deduplicated alerts.")
            return

        while True:
            scan_time = datetime.datetime.now(datetime.timezone.utc)
            print(f"\n[{scan_time.isoformat()}] Starting scheduled scan for recent logs...")
            
            # Clear the LAST_ALERT_TIME state for the incremental scan to re-evaluate
            global LAST_ALERT_TIME
            LAST_ALERT_TIME = {}
            
            # Fetch logs covering the full window for state maintenance
            full_logs = await fetch_logs(pool, limit=5000, since=scan_time - datetime.timedelta(minutes=CONFIG["window_minutes"]))
            alerts = detect_failed_logins(full_logs)

            for a in alerts:
                print(f"[ALERT] {a['rule']} - User:{a['user.name']} IP:{str(a['source.ip'])} "
                      f"Attempts:{a['count']} Time:{a['@timestamp']} Severity:{a['severity']}")
                await insert_alert_into_db(pool, a)

            if not alerts:
                print(f"[{datetime.datetime.now(datetime.timezone.utc).isoformat()}] No suspicious activity detected.")
            else:
                print(f"[*] Completed scheduled scan. Generated {len(alerts)} non-deduplicated alerts.")

            set_last_scan_time(scan_time)
            await asyncio.sleep(400)

if __name__ == "__main__":
    asyncio.run(main())