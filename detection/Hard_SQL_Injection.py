import asyncio
import argparse
import datetime
import re
import os
import sys
import urllib.parse
from collections import defaultdict
from psycopg.types.json import Json
from ipaddress import IPv4Address

# Ensure project root (collector is sibling of detection/)
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from collector.db import init_db  # existing DB functions

# --- CONFIGURATION ---
CONFIG = {
    "rate_threshold": 1,
    "window_minutes": 5,
    "alert_dedupe_seconds": 300,  # 5 minutes
}

# --- GLOBAL DEDUPLICATION STATE ---
LAST_ALERT_TIME = {}

# --- Improved SQLi regex (covers common variants and percent-encoded tokens) ---
sqli_regex = re.compile(
    r"(?ix)"
    r"("  # start group
    r"(\'\s*or\s*\'1\'\=\'1\'|or\s+1\s*\=\s*1|union\s+select|--|;\s*drop\b|/\*|\*/|\bselect\b.*\bfrom\b|\bexec\b|\bbenchmark\b|\bwaitfor\b)"
    r"|(%27|%22|%3D|%2D%2D|%3B|%2F%2A|%2A)"
    r")"
)


def detect_sqli(logs, rate_threshold=CONFIG["rate_threshold"], window_minutes=CONFIG["window_minutes"]):
    """
    Detect SQLi patterns in provided logs.
    Returns a list of alert dicts.
    """
    alerts = []
    ip_counter = defaultdict(list)
    dedupe_window_sec = CONFIG["alert_dedupe_seconds"]

    for log in logs:
        try:
            if "web" not in log.get("event", {}).get("category", []):
                continue

            # Prefer full URL (including querystring) when available
            full_url = str((log.get("url", {}).get("full") or ""))
            url_path = str((log.get("url", {}).get("original") or ""))
            url_to_check = (full_url or url_path).lower()

            # Body may be a string or structure -- stringify
            body_raw = log.get("http", {}).get("request", {}).get("body", "") or ""
            body = str(body_raw).lower()

            # Unquote percent-encoded payloads so our regex can match them
            url_unquoted = urllib.parse.unquote_plus(url_to_check)
            body_unquoted = urllib.parse.unquote_plus(body)

            combined_input = (url_unquoted + " " + body_unquoted).strip()

            # Debug: uncomment to print inspected input for each log
            # print("[DEBUG] Inspecting input:", combined_input)

            if sqli_regex.search(combined_input):
                ip = log.get("source", {}).get("ip")
                if not ip:
                    ip = "unknown"

                ts_raw = log.get("@timestamp")
                ts = (
                    datetime.datetime.fromisoformat(ts_raw)
                    if isinstance(ts_raw, str)
                    else ts_raw
                )

                ip_counter[ip].append(ts)
                recent_attempts = [
                    t for t in ip_counter[ip] if (ts - t).total_seconds() <= window_minutes * 60
                ]
                ip_counter[ip] = recent_attempts  # keep only relevant timestamps

                if len(recent_attempts) >= rate_threshold:
                    alert_id = f"SQLi|{ip}"
                    last_alert_ts = LAST_ALERT_TIME.get(alert_id)

                    # Deduplication check: skip if we've alerted recently for this ip
                    if last_alert_ts and (ts - last_alert_ts).total_seconds() < dedupe_window_sec:
                        # skip duplicate alert
                        continue

                    # severity logic: for immediate alerts, treat any detection >= rate_threshold as CRITICAL
                    severity = "CRITICAL" if len(recent_attempts) >= rate_threshold else "HIGH"

                    alert = {
                        "rule": "Suspicious Web Activity - SQLi",
                        "user.name": log.get("user", {}).get("name", "unknown"),
                        "source.ip": ip,
                        "@timestamp": ts.isoformat() if hasattr(ts, "isoformat") else str(ts),
                        "severity": severity,
                        "attack.technique": "SQLi",
                        "message": log.get("message"),
                        "http_method": log.get("http", {}).get("request", {}).get("method"),
                        "url": url_path,
                        "full_url": full_url or None,
                        "body": body_unquoted,
                        "count": len(recent_attempts),
                        "detected_input_snippet": combined_input[:1024],
                    }

                    alerts.append(alert)

                    # update last alert time
                    LAST_ALERT_TIME[alert_id] = ts

        except Exception as e:
            print(f"[!] detect_sqli error: {e}")
            continue

    return alerts


# --- Fetch web logs from DB (captures full URL from raw if present) ---
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
                    await cur.execute(
                        """
                        SELECT timestamp, username AS user_name, source_ip, outcome,
                               message, http_method, url_path, raw
                        FROM logs
                        WHERE 'web' = ANY(category) AND timestamp > %s
                        ORDER BY timestamp ASC
                        """,
                        (since,),
                    )
                else:
                    await cur.execute(
                        """
                        SELECT timestamp, username AS user_name, source_ip, outcome,
                               message, http_method, url_path, raw
                        FROM logs
                        WHERE 'web' = ANY(category)
                        ORDER BY timestamp ASC
                        """
                    )
                rows = await cur.fetchall()
                for r in rows:
                    raw_data = r[7] or {}

                    # try to get full URL from raw HTTP fields if present
                    full_url = None
                    try:
                        full_url = (
                            raw_data.get("http", {})
                            .get("request", {})
                            .get("url")
                        )
                    except Exception:
                        full_url = None

                    url_path = r[6] or ""
                    body = ""
                    try:
                        body = raw_data.get("http", {}).get("request", {}).get("body", "") or ""
                    except Exception:
                        body = ""

                    logs.append(
                        {
                            "@timestamp": r[0].isoformat() if hasattr(r[0], "isoformat") else str(r[0]),
                            "user": {"name": r[1] or "unknown"},
                            "source": {"ip": r[2]},
                            "event": {"category": ["web"], "outcome": r[3]},
                            "message": r[4],
                            "http": {"request": {"method": r[5], "body": body}},
                            "url": {"original": url_path, "full": full_url},
                            "raw": raw_data,
                        }
                    )
    except Exception as e:
        print(f"[!] DB query failed: {e}")
    return logs


# --- Insert alert into DB (ON CONFLICT DO NOTHING for dedupe at DB-level) ---
async def insert_alert(pool, alert: dict):
    insert_sql = """
    INSERT INTO alerts (
        timestamp, rule, user_name, source_ip,
        attempt_count, severity, technique, raw
    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    ON CONFLICT (timestamp, rule, source_ip) DO NOTHING;
    """
    try:
        ts_val = (
            datetime.datetime.fromisoformat(alert["@timestamp"]) if isinstance(alert["@timestamp"], str) else alert["@timestamp"]
        )
        src_ip = str(alert.get("source.ip") or alert.get("source_ip") or alert.get("source", {}).get("ip"))

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
            Json(raw_copy),
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
    parser = argparse.ArgumentParser()
    parser.add_argument("--full-scan", action="store_true", help="Scan all logs, not just new ones.")
    args = parser.parse_args()

    pool = await init_db()
    # Some init_db implementations require explicit open()
    try:
        await pool.open()
    except Exception:
        # Some pool implementations open lazily; ignore if not supported
        pass

    if args.full_scan:
        print(f"[{datetime.datetime.now(datetime.timezone.utc).isoformat()}] Starting FULL SQLi scan of all logs...")
        logs = await fetch_web_logs(pool, since=None)
        alerts = detect_sqli(logs)
        for alert in alerts:
            print(f"[ALERT] {alert['rule']} - User:{alert['user.name']} IP:{alert['source.ip']} Attempts:{alert['count']} Severity:{alert['severity']}")
            await insert_alert(pool, alert)
        if not alerts:
            print("[*] No SQL Injection detected (full scan).")
        return

    # --- Continuous scheduled scan for recent logs ---
    while True:
        scan_time = datetime.datetime.now(datetime.timezone.utc)
        print(f"\n[{scan_time.isoformat()}] Starting scheduled SQLi scan for recent logs...")
        last_scan = get_last_scan_time()

        # NOTE: do NOT clear LAST_ALERT_TIME here if you want dedupe across runs
        # If you intentionally want a fresh in-memory dedupe each run, uncomment the next line.
        # global LAST_ALERT_TIME
        # LAST_ALERT_TIME = {}

        lookback_time = scan_time - datetime.timedelta(minutes=CONFIG["window_minutes"]) 

        try:
            logs = await fetch_web_logs(pool, since=lookback_time)
        except Exception as e:
            print(f"[!] Connection error, reopening pool: {e}")
            pool = await init_db()
            try:
                await pool.open()
            except Exception:
                pass
            logs = await fetch_web_logs(pool, since=lookback_time)

        alerts = detect_sqli(logs)

        for alert in alerts:
            print(f"[ALERT] {alert['rule']} - User:{alert['user.name']} IP:{alert['source.ip']} Attempts:{alert['count']} Severity:{alert['severity']}")
            await insert_alert(pool, alert)

        if not alerts:
            print(f"[{datetime.datetime.now(datetime.timezone.utc).isoformat()}] No SQL Injection detected.")
        else:
            print(f"[*] Completed scheduled scan. Generated {len(alerts)} non-deduplicated alerts.")

        set_last_scan_time(scan_time)
        await asyncio.sleep(30)


if __name__ == "__main__":
    asyncio.run(main())
