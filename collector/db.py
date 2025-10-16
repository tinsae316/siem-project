# collector/db.py
import os
import logging
from datetime import datetime
from psycopg.types.json import Json
from psycopg.rows import dict_row
import psycopg
from psycopg_pool import AsyncConnectionPool
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

DB_URL = os.getenv("DATABASE_URL", "postgresql://user:password@localhost:5432/siem")

def safe_get(data, *keys):
    """Safely get a value from a nested dictionary, returning None if any key is missing."""
    for key in keys:
        if isinstance(data, dict):
            data = data.get(key)
        else:
            return None
    return data

def ensure_dt(timestamp_str):
    """Convert string to datetime object."""
    if not timestamp_str:
        return None
    try:
        return datetime.fromisoformat(timestamp_str)
    except Exception:
        return datetime.utcnow()

# -------------------- Database Initialization --------------------
async def init_db():
    """Initialize DB connection and create required tables."""
    try:
        pool = AsyncConnectionPool(conninfo=DB_URL, open=True)
        print("[*] Database connection pool created successfully.")

        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                # Logs table
                await cur.execute("""
                    CREATE TABLE IF NOT EXISTS logs (
                        id SERIAL PRIMARY KEY,
                        timestamp TIMESTAMPTZ,
                        source_ip INET,
                        source_port INT,
                        username TEXT,
                        host TEXT,
                        outcome TEXT,
                        severity SMALLINT,
                        category TEXT[],
                        action TEXT,
                        reason TEXT,
                        http_method TEXT,
                        http_status INT,
                        url_path TEXT,
                        user_agent TEXT,
                        attack_type TEXT,
                        attack_confidence TEXT,
                        labels TEXT[],
                        message TEXT,
                        raw JSONB,
                        destination_ip INET,
                        destination_port INT,
                        protocol TEXT
                    )
                """)
                # Alerts table
                await cur.execute("""
                    CREATE TABLE IF NOT EXISTS alerts (
                        timestamp TIMESTAMPTZ,
                        rule TEXT,
                        user_name TEXT,
                        source_ip INET,
                        attempt_count INT,
                        severity TEXT,
                        technique TEXT,
                        raw JSONB,
                        score FLOAT,
                        evidence TEXT,
                        PRIMARY KEY (timestamp, rule, source_ip)
                    )
                """)
        print("[*] 'logs' and 'alerts' tables checked/created successfully.")
        return pool
    except Exception as e:
        print(f"[!] Error initializing database: {e}")
        raise

# -------------------- Fetch Alerts --------------------
async def fetch_alerts(pool: AsyncConnectionPool, limit: int = 50, search: str = None):
    """Fetch alerts from the alerts table. Optional search filters rule, user_name, source_ip, technique."""
    query = """
        SELECT
            timestamp,
            rule,
            user_name,
            source_ip,
            attempt_count,
            severity,
            technique,
            raw,
            score,
            evidence
        FROM alerts
    """
    params = []
    if search:
        search_like = f"%{search}%"
        query += """
            WHERE rule ILIKE %s
               OR user_name ILIKE %s
               OR source_ip::TEXT ILIKE %s
               OR technique ILIKE %s
        """
        params.extend([search_like, search_like, search_like, search_like])

    query += " ORDER BY timestamp DESC LIMIT %s"
    params.append(limit)

    alerts = []
    try:
        async with pool.connection() as conn:
            async with conn.cursor(row_factory=dict_row) as cur:
                await cur.execute(query, params)
                rows = await cur.fetchall()
                for row in rows:
                    alerts.append({
                        "timestamp": row["timestamp"].isoformat(),
                        "source": {"ip": row["source_ip"]},
                        "user": {"name": row["user_name"]},
                        "event": {
                            "outcome": f"Severity {row['severity']}",
                            "category": row["rule"],
                            "technique": row["technique"],
                        },
                        "message": f"{row['rule']} detected (Score: {row['score']})",
                        "raw": row["raw"],
                    })
    except Exception as e:
        logger.exception("[!] Error fetching alerts from DB: %s", e)

    return alerts

# -------------------- Insert Alert --------------------
async def insert_alerts(pool: AsyncConnectionPool, alerts):
    """Insert multiple alerts into the alerts table, skipping duplicates."""
    if not alerts:
        return

    insert_sql = """
        INSERT INTO alerts (
            timestamp, rule, user_name, source_ip,
            attempt_count, severity, technique, raw, score, evidence
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (timestamp, rule, source_ip) DO NOTHING;
    """

    params_list = []
    for alert in alerts:
        ts_val = ensure_dt(alert.get("@timestamp"))
        params_list.append((
            ts_val,
            alert.get("rule"),
            alert.get("user.name"),
            alert.get("source.ip"),
            alert.get("count", 1),
            alert.get("severity"),
            alert.get("attack.technique"),
            Json(alert),
            alert.get("score"),
            alert.get("evidence")
        ))

    try:
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                batch_size = 100  # adjust if needed
                for i in range(0, len(params_list), batch_size):
                    await cur.executemany(insert_sql, params_list[i:i+batch_size])

        for alert in alerts:
            src_ip = alert.get("source.ip")
            print(f"[*] Alert saved: {alert.get('rule')} - Src: {src_ip}")

        logger.info(f"✅ Saved {len(alerts)} new alerts to DB (duplicates skipped).")
    except Exception as e:
        logger.exception("[!] Error inserting alerts into DB")
        for a in alerts:
            logger.debug("Alert data: %s", a)

# -------------------- Insert Log --------------------
async def insert_log(pool, log: dict):
    """Insert a log into the logs table."""
    if pool is None:
        print("[!] Error: Database pool not provided.")
        return

    try:
        log_data = log.copy()
        if 'id' in log_data:
            del log_data['id']

        log_timestamp = ensure_dt(log_data.get("timestamp"))

        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute("""
                    INSERT INTO logs (
                        timestamp, source_ip, source_port, username, host,
                        outcome, severity, category, action, reason,
                        http_method, http_status, url_path, user_agent,
                        attack_type, attack_confidence, labels, message, raw,
                        destination_ip, destination_port, protocol
                    ) VALUES (
                        %(timestamp)s, %(source_ip)s, %(source_port)s, %(username)s, %(host)s,
                        %(outcome)s, %(severity)s, %(category)s, %(action)s, %(reason)s,
                        %(http_method)s, %(http_status)s, %(url_path)s, %(user_agent)s,
                        %(attack_type)s, %(attack_confidence)s, %(labels)s, %(message)s, %(raw)s,
                        %(destination_ip)s, %(destination_port)s, %(protocol)s
                    )
                """, {
                    "timestamp": log_timestamp,
                    "source_ip": safe_get(log_data, 'source', 'ip'),
                    "source_port": safe_get(log_data, 'source', 'port'),
                    "username": safe_get(log_data, 'user', 'name'),
                    "host": safe_get(log_data, 'host', 'hostname'),
                    "outcome": safe_get(log_data, 'event', 'outcome'),
                    "severity": safe_get(log_data, 'event', 'severity'),
                    "category": safe_get(log_data, 'event', 'category'),
                    "action": safe_get(log_data, 'event', 'action'),
                    "reason": safe_get(log_data, 'event', 'reason'),
                    "http_method": safe_get(log_data, 'http', 'request', 'method'),
                    "http_status": safe_get(log_data, 'http', 'response', 'status_code'),
                    "url_path": safe_get(log_data, 'url', 'path'),
                    "user_agent": safe_get(log_data, 'user_agent', 'original'),
                    "attack_type": safe_get(log_data, 'attack', 'technique'),
                    "attack_confidence": safe_get(log_data, 'attack', 'confidence'),
                    "labels": log_data.get('labels'),
                    "message": log_data.get('message'),
                    "raw": Json(log_data),
                    "destination_ip": safe_get(log_data, 'destination', 'ip'),
                    "destination_port": safe_get(log_data, 'destination', 'port'),
                    "protocol": safe_get(log_data, 'network', 'transport'),
                })
        print("[*] Log successfully inserted into the database.")
    except Exception as e:
        print(f"[!] Error inserting log into database: {e}")
        print(f"Failed log data: {log_data}")
