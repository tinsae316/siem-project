# detection/Suspicious_admin.py
import asyncio
import datetime
from collections import defaultdict
from psycopg.types.json import Json
from collector.db import init_db  # existing DB functions

# --- Known admins ---
KNOWN_ADMINS = {"bob", "superuser"}  # only these users are allowed to create new admins

# --- Detection function ---
def detect_suspicious_admin_creation(logs, known_admins=KNOWN_ADMINS, window_minutes=5, max_admin_creations=1):
    alerts = []
    keywords = ["new admin", "added to admin group", "grant admin", "privilege escalation", "sudo useradd"]
    creations = defaultdict(list)

    for log in logs:
        if log["event"]["category"] == "authentication" and log["event"]["outcome"] == "success":
            msg = log.get("message", "").lower()
            creator = log["user"]["name"]
            ts = log["@timestamp"]

            if any(k in msg for k in keywords):
                creations[creator].append(ts)
                recent = [t for t in creations[creator] if (ts - t).total_seconds() <= window_minutes * 60]

                if creator not in known_admins:
                    severity = "CRITICAL"
                elif len(recent) > max_admin_creations:
                    severity = "CRITICAL"
                else:
                    severity = "HIGH"

                alerts.append({
                    "rule": "Suspicious Admin Account Creation",
                    "user.name": creator,
                    "source.ip": log["source"]["ip"],
                    "@timestamp": ts.isoformat(),
                    "severity": severity,
                    "attack.technique": "privilege_escalation",
                    "message": log["message"]
                })
    return alerts

# --- Fetch admin-related logs from DB ---
async def fetch_admin_logs(pool):
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
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
    ts_val = alert.get("@timestamp")
    ts_val = ts_val if isinstance(ts_val, datetime.datetime) else datetime.datetime.fromisoformat(ts_val)

    # Convert source IP to string
    src_ip = str(alert.get("source.ip")) if alert.get("source.ip") else None

    # Ensure JSON serializable for raw
    raw_copy = {k: (str(v) if isinstance(v, (datetime.datetime, datetime.date, type(alert.get("source.ip")))) else v)
                for k, v in alert.items()}

    params = {
        "timestamp": ts_val,
        "rule": alert.get("rule"),
        "user_name": alert.get("user.name"),
        "source_ip": src_ip,
        "attempt_count": 1,
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
    pool = await init_db()
    logs = await fetch_admin_logs(pool)
    alerts = detect_suspicious_admin_creation(logs)

    if alerts:
        for alert in alerts:
            await insert_alert_into_db(pool, alert)
    else:
        print("[*] No suspicious admin activity detected.")

if __name__ == "__main__":
    asyncio.run(main())
