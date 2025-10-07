# detection/Hard_XSS_Detection.py
import asyncio
import datetime
import re
from collections import defaultdict
from psycopg.types.json import Json
from collector.db import init_db  # your existing DB init function
from ipaddress import IPv4Address

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

# --- Fetch web logs ---
async def fetch_web_logs(pool):
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute("""
                SELECT timestamp, username, source_ip, http_method, url_path, raw
                FROM logs
                WHERE 'web' = ANY(category)
                ORDER BY timestamp ASC
            """)
            rows = await cur.fetchall()
            logs = []
            for r in rows:
                logs.append({
                    "@timestamp": r[0],  # may still be string
                    "user": {"name": r[1]},
                    "source": {"ip": r[2]},
                    "http_method": r[3],
                    "url": r[4],
                    "raw": r[5]
                })
            return logs

# --- XSS detection ---
def detect_hard_xss(logs, rate_threshold=3, window_minutes=5):
    alerts = []
    ip_counter = defaultdict(list)

    for log in logs:
        # Convert timestamp if necessary
        ts = log["@timestamp"]
        if isinstance(ts, str):
            ts = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))

        url = str(log.get("url", ""))
        raw_data = str(log.get("raw", ""))
        http_method = log.get("http_method", "")

        combined_input = url + " " + raw_data

        if xss_regex.search(combined_input):
            ip = log["source"]["ip"]
            if isinstance(ip, IPv4Address):
                ip = str(ip)

            # Track attempts per IP
            ip_counter[ip].append(ts)
            recent_attempts = [t for t in ip_counter[ip] if (ts - t).total_seconds() <= window_minutes * 60]

            severity = "HIGH"
            if len(recent_attempts) >= rate_threshold:
                severity = "CRITICAL"

            alerts.append({
                "rule": "Advanced XSS Detected",
                "user.name": log["user"]["name"],
                "source.ip": ip,
                "@timestamp": ts.isoformat(),
                "severity": severity,
                "attack.technique": "XSS",
                "http_method": http_method,
                "url": url,
                "raw": raw_data
            })
    return alerts

# --- Insert alert into DB ---
async def insert_alert_into_db(pool, alert):
    insert_sql = """
    INSERT INTO alerts (
        timestamp, rule, user_name, source_ip,
        severity, technique, raw
    ) VALUES (
        %(timestamp)s, %(rule)s, %(user_name)s, %(source_ip)s,
        %(severity)s, %(technique)s, %(raw)s
    )
    """
    params = {
        "timestamp": alert["@timestamp"],
        "rule": alert["rule"],
        "user_name": alert["user.name"],
        "source_ip": alert["source.ip"],
        "severity": alert["severity"],
        "technique": alert["attack.technique"],
        "raw": Json(alert["raw"])
    }
    try:
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(insert_sql, params)
        print(f"[*] Alert saved: {alert['rule']} - {alert['user.name']} @ {alert['source.ip']}")
    except Exception as e:
        print(f"[!] Error inserting alert into DB: {e}")
        print("Alert data:", alert)

# --- Main ---
async def main():
    pool = await init_db()
    logs = await fetch_web_logs(pool)
    alerts = detect_hard_xss(logs)

    if alerts:
        for alert in alerts:
            await insert_alert_into_db(pool, alert)
    else:
        print("[*] No advanced XSS detected.")

if __name__ == "__main__":
    asyncio.run(main())
