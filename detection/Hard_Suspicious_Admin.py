import asyncio
import datetime
from collections import defaultdict
from psycopg.types.json import Json
from collector.db import init_db
import os
import argparse
from ipaddress import IPv4Address, IPv6Address

LAST_SCAN_FILE = "last_scan_suspicious_admin.txt"

# --- CONFIGURATION (Added alert_dedupe_seconds) ---
CONFIG = {
    "window_minutes": 5,
    "max_admin_creations": 1,
    "alert_dedupe_seconds": 3600, # Set a long dedupe window (1 hour) for critical events like this
}

# --- GLOBAL DEDUPLICATION STATE ---
# Key: Rule|User (the creator) -> Value: last alert timestamp
LAST_ALERT_TIME = {}

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
async def fetch_admin_logs(pool, since=None):
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            if since:
                await cur.execute("""
                    SELECT timestamp, username, source_ip, outcome, message
                    FROM logs
                    WHERE outcome = 'success' AND message ILIKE '%admin%' AND timestamp > %s
                    ORDER BY timestamp ASC
                """, (since,))
            else:
                await cur.execute("""
                    SELECT timestamp, username, source_ip, outcome, message
                    FROM logs
                    WHERE outcome = 'success' AND message ILIKE '%admin%'
                    ORDER BY timestamp ASC
                """)
            rows = await cur.fetchall()
            logs = []
            for r in rows:
                logs.append({
                    "@timestamp": r[0],
                    "user": {"name": r[1]},
                    "source": {"ip": r[2]},
                    "event": {"category": "authentication", "outcome": r[3]},
                    "message": r[4]
                })
            return logs

# ---------------- Detection (Updated for Deduplication) ----------------
KNOWN_ADMINS = {"bob", "superuser"}

def detect_suspicious_admin_creation(logs, known_admins=KNOWN_ADMINS):
    alerts = []
    keywords = ["new admin", "added to admin group", "grant admin", "privilege escalation", "sudo useradd"]
    creations = defaultdict(list)
    
    window_minutes = CONFIG["window_minutes"]
    max_admin_creations = CONFIG["max_admin_creations"]
    dedupe_window_sec = CONFIG["alert_dedupe_seconds"]

    for log in logs:
        if log["event"]["category"] == "authentication" and log["event"]["outcome"] == "success":
            msg = log.get("message", "").lower()
            creator = log["user"]["name"]
            ts = ensure_dt(log["@timestamp"])

            if any(k in msg for k in keywords):
                creations[creator].append(ts)
                recent = [t for t in creations[creator] if (ts - t).total_seconds() <= window_minutes * 60]
                creations[creator] = recent # Keep state clean

                # Only proceed if there's an actual incident (e.g., more than one creation by a known admin)
                # or if an unknown user is creating anything.
                is_suspicious = (creator not in known_admins and len(recent) >= 1) or \
                                (creator in known_admins and len(recent) > max_admin_creations)
                
                if is_suspicious:
                    
                    # --- Deduplication Check ---
                    # Dedupe based on the *creator* user, as this is a single incident type.
                    alert_id = f"Suspicious Admin Account Creation|{creator}"
                    last_alert_ts = LAST_ALERT_TIME.get(alert_id)
                    
                    # Check: Skip alert creation if a recent alert already exists for this creator
                    if last_alert_ts and (ts - last_alert_ts).total_seconds() < dedupe_window_sec:
                        continue
                    # --- End Deduplication Check ---
                    
                    # Determine severity and prepare IP
                    severity = "CRITICAL" if creator not in known_admins or len(recent) > max_admin_creations else "HIGH"

                    src_ip = log["source"]["ip"]
                    if isinstance(src_ip, (IPv4Address, IPv6Address)):
                        src_ip = str(src_ip)
                        
                    # Create the alert only if it passes the deduplication check
                    alerts.append({
                        "rule": "Suspicious Admin Account Creation",
                        "user.name": creator,
                        "source.ip": src_ip,
                        "@timestamp": ts.isoformat(),
                        "severity": severity,
                        "attack.technique": "privilege_escalation",
                        "message": log["message"],
                        "count": len(recent) # Added count for consistency
                    })
                    
                    # Update the last alert time
                    LAST_ALERT_TIME[alert_id] = ts
                    
    return alerts

# ---------------- Insert alerts ----------------
async def insert_alert_into_db(pool, alert: dict):
    # insert_sql already has ON CONFLICT (timestamp, rule, source_ip) DO NOTHING;
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
    src_ip = alert.get("source.ip")
    if isinstance(src_ip, (IPv4Address, IPv6Address)):
        src_ip = str(src_ip)

    # Convert any non-serializable fields to string for JSONB
    raw_copy = {}
    for k, v in alert.items():
        if isinstance(v, (datetime.datetime, datetime.date, IPv4Address, IPv6Address)):
            raw_copy[k] = str(v)
        else:
            raw_copy[k] = v

    params = {
        "timestamp": ts_val,
        "rule": alert.get("rule"),
        "user_name": alert.get("user.name"),
        "source_ip": src_ip,
        "attempt_count": alert.get("count", 1), # Use count from detection logic
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

# ---------------- Main ----------------
async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--full-scan", action="store_true", help="Scan all logs, not just new ones.")
    args = parser.parse_args()

    pool = await init_db()

    if args.full_scan:
        print("[*] Starting FULL scan of admin logs...")
        logs = await fetch_admin_logs(pool, since=None)
        alerts = detect_suspicious_admin_creation(logs)
        for alert in alerts:
            # Print the alert only if it passed the in-memory check
            print(f"[ALERT] {alert['rule']} - User:{alert['user.name']} IP:{alert['source.ip']} Attempts:{alert['count']} Severity:{alert['severity']}")
            await insert_alert_into_db(pool, alert)
        print(f"[✅] Suspicious Admin Scan complete. Generated {len(alerts)} non-deduplicated alerts.")
        return

    while True:
        scan_time = datetime.datetime.now(datetime.timezone.utc)
        last_scan = get_last_scan_time()
        print(f"[*] Scheduled scan starting at {scan_time.isoformat()}...")
        
        # Clear the LAST_ALERT_TIME state for the incremental scan to re-evaluate
        global LAST_ALERT_TIME
        LAST_ALERT_TIME = {}
        
        # Fetch a wider window of logs to ensure detection logic works correctly
        lookback_time = scan_time - datetime.timedelta(minutes=CONFIG["window_minutes"])
        logs = await fetch_admin_logs(pool, since=lookback_time)
        
        alerts = detect_suspicious_admin_creation(logs)
        
        for alert in alerts:
            # Print the alert only if it passed the in-memory check
            print(f"[ALERT] {alert['rule']} - User:{alert['user.name']} IP:{alert['source.ip']} Attempts:{alert['count']} Severity:{alert['severity']}")
            await insert_alert_into_db(pool, alert)
        
        if not alerts:
            print("[*] No suspicious admin creation detected.")
        else:
            print(f"[*] Completed scheduled scan. Generated {len(alerts)} non-deduplicated alerts.")
            
        set_last_scan_time(scan_time)
        await asyncio.sleep(40)

if __name__ == "__main__":
    asyncio.run(main())