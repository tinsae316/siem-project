# detection/File_Ransomware_Detector.py
import asyncio
import datetime
import os
import math
from collections import defaultdict, deque
from ipaddress import ip_address, ip_network
from psycopg.types.json import Json
import argparse
import sys

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from collector.db import init_db

# ---------------- Configuration ----------------
PRIVATE_NETS = [
    ip_network("10.0.0.0/8"),
    ip_network("192.168.0.0/16"),
    ip_network("172.16.0.0/12"),
]

SENSITIVE_EXTENSIONS = [".db", ".csv", ".bak", ".sql"]
RANSOMWARE_EXTENSIONS = [".locked", ".encrypted", ".crypt"]
FILE_THRESHOLD = 20
WINDOW_MINUTES = 5
LAST_SCAN_FILE = "last_scan_file.txt"

# ---------------- Utility Functions ----------------
def shannon_entropy(s: str) -> float:
    """Detect randomness in filenames."""
    if not s:
        return 0
    probs = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)

def is_private_ip(ip: str) -> bool:
    try:
        return any(ip_address(ip) in net for net in PRIVATE_NETS)
    except ValueError:
        return False

def extract_filename(file_info: dict) -> str:
    name = file_info.get("name")
    if name:
        return name.lower().strip()
    path = file_info.get("path", "")
    return os.path.basename(path).lower().strip() if path else ""

def get_last_scan_time():
    if os.path.exists(LAST_SCAN_FILE):
        with open(LAST_SCAN_FILE, "r") as f:
            return datetime.datetime.fromisoformat(f.read().strip())
    return None

def set_last_scan_time(ts):
    with open(LAST_SCAN_FILE, "w") as f:
        f.write(ts.isoformat())

# ---------------- Detection Function ----------------
def detect_suspicious_file_activity(logs, file_threshold=FILE_THRESHOLD, window_minutes=WINDOW_MINUTES):
    alerts = []
    file_modifications = defaultdict(deque)
    file_uploads = defaultdict(list)

    for log in logs:
        ts = log.get("@timestamp")
        if isinstance(ts, str):
            ts = datetime.datetime.fromisoformat(ts)

        user = log.get("user", {}).get("name", "unknown")
        ip = str(log.get("source", {}).get("ip", "unknown"))
        key = (user, ip)
        event_type = log.get("event", {}).get("category", [])

        file_info = log.get("file", {})
        file_name = extract_filename(file_info)
        network_dest = log.get("destination", {}).get("ip")

        # Mass Encryption / Suspicious Renames
        if "file" in event_type:
            if any(file_name.endswith(ext) for ext in RANSOMWARE_EXTENSIONS) or shannon_entropy(file_name) > 4.0:
                file_modifications[key].append(ts)
                # sliding window
                while file_modifications[key] and (ts - file_modifications[key][0]).total_seconds() > window_minutes * 60:
                    file_modifications[key].popleft()
                if len(file_modifications[key]) >= file_threshold:
                    alerts.append({
                        "rule": "Mass File Encryption Detected",
                        "user.name": user,
                        "source.ip": ip,
                        "@timestamp": ts.isoformat(),
                        "count": len(file_modifications[key]),
                        "severity": "CRITICAL",
                        "attack.technique": "ransomware",
                        "example_file": file_name
                    })

        # Sensitive File Upload
        if "network" in event_type and file_name:
            if any(file_name.endswith(ext) for ext in SENSITIVE_EXTENSIONS) and network_dest and not is_private_ip(network_dest):
                file_uploads[key].append((ts, file_name, network_dest))
                alerts.append({
                    "rule": "Sensitive File Upload",
                    "user.name": user,
                    "source.ip": ip,
                    "@timestamp": ts.isoformat(),
                    "severity": "HIGH",
                    "attack.technique": "data_exfiltration",
                    "file": file_name,
                    "destination.ip": str(network_dest)
                })

    return alerts

# ---------------- DB Helpers ----------------
async def ensure_alerts_table(pool):
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

async def insert_alert(pool, alert: dict):
    insert_sql = """
    INSERT INTO alerts (
        timestamp, rule, user_name, source_ip,
        attempt_count, severity, technique, raw
    ) VALUES (%(timestamp)s, %(rule)s, %(user_name)s, %(source_ip)s,
              %(attempt_count)s, %(severity)s, %(technique)s, %(raw)s)
    """
    ts_val = alert.get("@timestamp")
    if isinstance(ts_val, str):
        ts_val = datetime.datetime.fromisoformat(ts_val)

    params = {
        "timestamp": ts_val,
        "rule": alert.get("rule"),
        "user_name": alert.get("user.name"),
        "source_ip": str(alert.get("source.ip")),
        "attempt_count": alert.get("count", 1),
        "severity": alert.get("severity"),
        "technique": alert.get("attack.technique"),
        "raw": Json(alert)
    }

    try:
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(insert_sql, params)
        print(f"[*] Alert saved: {alert['rule']} - User:{alert['user.name']} @ {alert['source.ip']}")
    except Exception as e:
        print(f"[!] Error inserting alert: {e}\nAlert: {alert}")

# ---------------- Fetch Logs ----------------
async def fetch_logs(pool, limit=5000, since=None):
    logs = []
    try:
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                if since:
                    await cur.execute("""
                        SELECT timestamp, username, source_ip, destination_ip, category, message, raw
                        FROM logs
                        WHERE timestamp > %s AND ('file' = ANY(category) OR 'network' = ANY(category))
                        ORDER BY timestamp ASC
                        LIMIT %s
                    """, (since, limit))
                else:
                    await cur.execute("""
                        SELECT timestamp, username, source_ip, destination_ip, category, message, raw
                        FROM logs
                        WHERE 'file' = ANY(category) OR 'network' = ANY(category)
                        ORDER BY timestamp ASC
                        LIMIT %s
                    """, (limit,))
                rows = await cur.fetchall()

        for r in rows:
            raw = r[6] or {}
            logs.append({
                "@timestamp": r[0],
                "user": {"name": r[1]},
                "source": {"ip": r[2]},
                "destination": {"ip": r[3]},
                "event": {"category": r[4]},
                "message": r[5],
                "file": raw.get("file", {}),
                "raw": raw
            })
    except Exception as e:
        print(f"[!] Error fetching logs: {e}")
    return logs

# ---------------- Main Runner ----------------
async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--full-scan", action="store_true", help="Scan all logs, not just new ones.")
    args = parser.parse_args()

    pool = await init_db()
    await ensure_alerts_table(pool)

    if args.full_scan:
        print(f"[{datetime.datetime.now(datetime.timezone.utc).isoformat()}] Starting FULL scan of file/network logs...")
        logs = await fetch_logs(pool, limit=5000, since=None)
        alerts = detect_suspicious_file_activity(logs)
        if alerts:
            for a in alerts:
                print(f"[ALERT] {a['rule']} - User:{a['user.name']} IP:{a['source.ip']} "
                      f"Time:{a['@timestamp']} Severity:{a['severity']}")
                await insert_alert(pool, a)
        else:
            print("[*] No suspicious activity detected (full scan).")
        return

    # Continuous scheduled scanning
    while True:
        scan_time = datetime.datetime.now(datetime.timezone.utc)
        print(f"\n[{scan_time.isoformat()}] Starting scheduled file/network log scan...")
        last_scan = get_last_scan_time()
        logs = await fetch_logs(pool, limit=5000, since=last_scan)
        alerts = detect_suspicious_file_activity(logs)

        if alerts:
            for a in alerts:
                print(f"[ALERT] {a['rule']} - User:{a['user.name']} IP:{a['source.ip']} "
                      f"Time:{a['@timestamp']} Severity:{a['severity']}")
                await insert_alert(pool, a)
        else:
            print(f"[{datetime.datetime.now(datetime.timezone.utc).isoformat()}] No suspicious activity detected.")

        set_last_scan_time(scan_time)
        await asyncio.sleep(40)


if __name__ == "__main__":
    asyncio.run(main())
