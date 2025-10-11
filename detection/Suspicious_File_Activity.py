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
ALERT_DEDUPE_SECONDS_RANSOMWARE = 3600  # 1 hour dedupe for critical event
ALERT_DEDUPE_SECONDS_EXFIL = 300 # 5 minutes dedupe for exfil event
LAST_SCAN_FILE = "last_scan_file.txt"

# --- GLOBAL DEDUPLICATION STATE ---
# Key: Rule|User|Source IP -> Value: last alert timestamp
LAST_ALERT_TIME = {}

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

def ensure_dt(ts):
    if isinstance(ts, datetime.datetime):
        # Ensure it is UTC aware
        return ts if ts.tzinfo else ts.replace(tzinfo=datetime.timezone.utc)
    if isinstance(ts, str):
        try:
            return datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            return datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)
    return datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)

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
    
    dedupe_window_ransomware = ALERT_DEDUPE_SECONDS_RANSOMWARE
    dedupe_window_exfil = ALERT_DEDUPE_SECONDS_EXFIL

    for log in logs:
        ts = log.get("@timestamp")
        ts_dt = ensure_dt(ts)

        user = log.get("user", {}).get("name", "unknown")
        ip = str(log.get("source", {}).get("ip", "unknown"))
        key = (user, ip)
        event_type = log.get("event", {}).get("category", [])

        file_info = log.get("file", {})
        file_name = extract_filename(file_info)
        
        # Ensure network_dest is a string for is_private_ip check
        network_dest = str(log.get("destination", {}).get("ip")) if log.get("destination", {}).get("ip") else None
        
        # --- Rule 1: Mass Encryption / Suspicious Renames ---
        if "file" in event_type:
            # Check for ransomware extension or high entropy (potential encryption)
            if any(file_name.endswith(ext) for ext in RANSOMWARE_EXTENSIONS) or shannon_entropy(file_name) > 4.0:
                file_modifications[key].append(ts_dt)
                
                # Sliding window logic
                while file_modifications[key] and (ts_dt - file_modifications[key][0]).total_seconds() > window_minutes * 60:
                    file_modifications[key].popleft()
                    
                if len(file_modifications[key]) >= file_threshold:
                    rule = "Mass File Encryption Detected"
                    alert_id = f"{rule}|{user}|{ip}"
                    last_alert_ts = LAST_ALERT_TIME.get(alert_id)
                    
                    # Deduplication Check
                    if not last_alert_ts or (ts_dt - last_alert_ts).total_seconds() >= dedupe_window_ransomware:
                        alerts.append({
                            "rule": rule,
                            "user.name": user,
                            "source.ip": ip,
                            "@timestamp": ts_dt.isoformat(),
                            "count": len(file_modifications[key]),
                            "severity": "CRITICAL",
                            "attack.technique": "ransomware",
                            "example_file": file_name
                        })
                        LAST_ALERT_TIME[alert_id] = ts_dt

        # --- Rule 2: Sensitive File Upload (Exfiltration) ---
        if "network" in event_type and file_name and network_dest:
            if any(file_name.endswith(ext) for ext in SENSITIVE_EXTENSIONS) and not is_private_ip(network_dest):
                rule = "Sensitive File Upload (Exfiltration)"
                # Use a specific destination IP in the key for this rule to differentiate exfiltration targets
                alert_id = f"{rule}|{user}|{ip}|{network_dest}" 
                last_alert_ts = LAST_ALERT_TIME.get(alert_id)
                
                # Deduplication Check
                if not last_alert_ts or (ts_dt - last_alert_ts).total_seconds() >= dedupe_window_exfil:
                    alerts.append({
                        "rule": rule,
                        "user.name": user,
                        "source.ip": ip,
                        "@timestamp": ts_dt.isoformat(),
                        "severity": "HIGH",
                        "attack.technique": "data_exfiltration",
                        "file": file_name,
                        "destination.ip": network_dest,
                        "count": 1 # Single event alert
                    })
                    LAST_ALERT_TIME[alert_id] = ts_dt

    return alerts

# ---------------- DB Helpers ----------------
async def ensure_alerts_table(pool):
    # Added UNIQUE constraint for robust DB-level deduplication
    create_sql = """
    CREATE TABLE IF NOT EXISTS alerts (
        id SERIAL PRIMARY KEY,
        timestamp TIMESTAMPTZ NOT NULL,
        rule TEXT NOT NULL,
        username TEXT,
        source_ip INET,
        attempt_count INT,
        severity TEXT,
        attack_technique TEXT,
        raw JSONB,
        UNIQUE (timestamp, rule, source_ip)
    );
    """
    try:
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(create_sql)
        print("[*] 'alerts' table checked/created successfully.")
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
    ON CONFLICT (timestamp, rule, source_ip) DO NOTHING;
    """
    ts_val = alert.get("@timestamp")
    if isinstance(ts_val, str):
        ts_val = ensure_dt(ts_val)

    # Ensure all fields for raw are JSON serializable (including ipaddress objects)
    raw_copy = {}
    for k, v in alert.items():
        if k == "@timestamp":
            raw_copy[k] = ts_val.isoformat()
        elif isinstance(v, (datetime.datetime, datetime.date, ip_address, ip_network)):
            raw_copy[k] = str(v)
        else:
            raw_copy[k] = v

    params = {
        "timestamp": ts_val,
        "rule": alert.get("rule"),
        "user_name": alert.get("user.name"),
        "source_ip": str(alert.get("source.ip")),
        "attempt_count": alert.get("count", 1),
        "severity": alert.get("severity"),
        "technique": alert.get("attack.technique"),
        "raw": Json(raw_copy)
    }

    try:
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(insert_sql, params)
        print(f"[*] Alert saved: {alert['rule']} - User:{alert['user.name']} @ {alert['source.ip']}")
    except Exception as e:
        print(f"[!] Error inserting alert: {e}\nAlert: {alert}")

# ---------------- Fetch Logs (FIXED) ----------------
async def fetch_logs(pool, limit=5000, since=None):
    """
    Fetches file and network related logs since a given timestamp.
    The 'since' parameter is set by the calling function (main).
    """
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
    
    # Use context manager to ensure safe pool closure
    async with pool:
        await ensure_alerts_table(pool)

        if args.full_scan:
            print(f"[{datetime.datetime.now(datetime.timezone.utc).isoformat()}] Starting FULL scan of file/network logs...")
            # FULL SCAN: Pass since=None to fetch_logs
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
            
            # Use a lookback time that covers the full window to maintain detection state
            lookback_time = scan_time - datetime.timedelta(minutes=WINDOW_MINUTES)
            
            # Clear the LAST_ALERT_TIME state for the incremental scan to re-evaluate
            global LAST_ALERT_TIME
            LAST_ALERT_TIME = {}
            
            logs = await fetch_logs(pool, limit=5000, since=lookback_time)
            alerts = detect_suspicious_file_activity(logs)

            if alerts:
                for a in alerts:
                    print(f"[ALERT] {a['rule']} - User:{a['user.name']} IP:{a['source.ip']} "
                          f"Time:{a['@timestamp']} Severity:{a['severity']}")
                    await insert_alert(pool, a)
                print(f"[*] Completed scheduled scan. Generated {len(alerts)} non-deduplicated alerts.")
            else:
                print(f"[{datetime.datetime.now(datetime.timezone.utc).isoformat()}] No suspicious activity detected.")

            set_last_scan_time(scan_time)
            await asyncio.sleep(40)


if __name__ == "__main__":
    asyncio.run(main())
