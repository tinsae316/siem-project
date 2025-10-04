import asyncio
import datetime
import os
import math
from collections import defaultdict, deque
from ipaddress import ip_address, ip_network
from psycopg.types.json import Json
from collector.db import init_db  # reuse existing DB init


# -------- Utility Functions --------
PRIVATE_NETS = [
    ip_network("10.0.0.0/8"),
    ip_network("192.168.0.0/16"),
    ip_network("172.16.0.0/12"),
]

def shannon_entropy(s: str) -> float:
    """Detect randomness in filenames (common in ransomware)."""
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
    """
    Extract the filename from 'name' if present, else from 'path'.
    Returns normalized lowercase string.
    """
    name = file_info.get("name")
    if name:
        return name.lower().strip()
    path = file_info.get("path", "")
    return os.path.basename(path).lower().strip() if path else ""


# -------- Detection Function --------
def detect_suspicious_file_activity(logs, file_threshold=20, window_minutes=5):
    alerts = []
    file_modifications = defaultdict(deque)
    file_uploads = defaultdict(list)

    sensitive_extensions = [".db", ".csv", ".bak", ".sql"]
    ransomware_extensions = [".locked", ".encrypted", ".crypt"]

    for log in logs:
        ts = log.get("@timestamp")
        if isinstance(ts, str):
            ts = datetime.datetime.fromisoformat(ts)

        user = log.get("user", {}).get("name", "unknown")
        ip = str(log.get("source", {}).get("ip", "unknown"))
        key = (user, ip)

        event_type = log.get("event", {}).get("category", [])

        # Extract filename from log
        file_info = log.get("file", {})
        file_name = extract_filename(file_info)

        network_dest = log.get("destination", {}).get("ip")

        # --- Case 1: Mass Encryption / Suspicious Renames ---
        if "file" in event_type:
            if any(file_name.endswith(ext) for ext in ransomware_extensions) or shannon_entropy(file_name) > 4.0:
                file_modifications[key].append(ts)

                # keep only recent events in sliding window
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

        # --- Case 2: Sensitive File Upload to External IP ---
        if "network" in event_type and file_name:
            if any(file_name.endswith(ext) for ext in sensitive_extensions) and network_dest and not is_private_ip(network_dest):
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


# -------- Fetch logs from DB --------
async def fetch_file_and_network_logs(pool, limit=5000):
    logs = []
    try:
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute("""
                    SELECT timestamp, username, source_ip, destination_ip,
                           category, message, raw
                    FROM logs
                    WHERE 'file' = ANY(category) OR 'network' = ANY(category)
                    ORDER BY timestamp DESC
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
                "file": raw.get("file", {}),  # now correctly supports 'path'
            })
    except Exception as e:
        print(f"[!] Error fetching logs: {e}")
    return logs


# -------- Insert alert into DB --------
async def insert_alert(pool, alert: dict):
    insert_sql = """
    INSERT INTO alerts (
        timestamp, rule, user_name, source_ip,
        attempt_count, severity, technique, raw
    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    """

    ts_val = datetime.datetime.fromisoformat(alert["@timestamp"])
    src_ip = str(alert.get("source.ip"))

    params = (
        ts_val,
        alert.get("rule"),
        alert.get("user.name"),
        src_ip,
        alert.get("count", 1),
        alert.get("severity"),
        alert.get("attack.technique"),
        Json(alert)
    )

    try:
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(insert_sql, params)
        print(f"[*] Alert saved: {alert['rule']} - User:{alert['user.name']} @ {src_ip}")
    except Exception as e:
        print(f"[!] Error inserting alert into DB: {e}")
        print("Alert data:", alert)


# -------- Main Runner --------
async def main():
    pool = await init_db()
    logs = await fetch_file_and_network_logs(pool)
    alerts = detect_suspicious_file_activity(logs)

    if alerts:
        for a in alerts:
            await insert_alert(pool, a)
            print(f"[ALERT] {a['rule']} - User:{a['user.name']} IP:{a['source.ip']} "
                  f"Time:{a['@timestamp']} Severity:{a['severity']}")
    else:
        print("[*] No suspicious file activity detected.")


if __name__ == "__main__":
    asyncio.run(main())
