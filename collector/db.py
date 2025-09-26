# collector/db.py
import psycopg
from psycopg_pool import AsyncConnectionPool
import os
from dotenv import load_dotenv
from datetime import datetime
from psycopg.types.json import Json

load_dotenv()

DB_URL = os.getenv("DATABASE_URL", "postgresql://user:password@localhost:5432/siem")

def safe_get(data, *keys):
    """Safely gets a value from a nested dictionary, returning None if any key is missing."""
    for key in keys:
        if isinstance(data, dict):
            data = data.get(key)
        else:
            return None
    return data

async def init_db():
    try:
        pool = AsyncConnectionPool(conninfo=DB_URL, open=True)
        print("[*] Database connection pool created successfully.")
        
        # We need a connection from the pool to execute the DDL statement
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
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
        
        print("[*] 'logs' table checked/created successfully.")
        return pool
    except Exception as e:
        print(f"[!] Error initializing database: {e}")
        raise

async def insert_log(pool, log: dict):
    """Inserts a log into the database using the provided pool."""
    if pool is None:
        print("[!] Error: Database pool not provided.")
        return

    try:
        # Convert the timestamp string to a datetime object
        log_timestamp_str = log.get('timestamp')
        log_timestamp = datetime.fromisoformat(log_timestamp_str) if log_timestamp_str else None

        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    """
                    INSERT INTO logs (
                        timestamp, source_ip, source_port, username, host,
                        outcome, severity, category, action, reason,
                        http_method, http_status, url_path, user_agent,
                        attack_type, attack_confidence, labels, message, raw, destination_ip, destination_port, protocol
                    ) VALUES (
                        %(timestamp)s, %(source_ip)s, %(source_port)s, %(username)s, %(host)s,
                        %(outcome)s, %(severity)s, %(category)s, %(action)s, %(reason)s,
                        %(http_method)s, %(http_status)s, %(url_path)s, %(user_agent)s,
                        %(attack_type)s, %(attack_confidence)s, %(labels)s, %(message)s, %(raw)s, %(destination_ip)s, %(destination_port)s, %(protocol)s
                    )
                    """,
                    {
                        "timestamp": log_timestamp,
                        "source_ip": safe_get(log, 'source', 'ip'),
                        "source_port": safe_get(log, 'source', 'port'),
                        "username": safe_get(log, 'user', 'name'),
                        "host": safe_get(log, 'host', 'hostname'),
                        "outcome": safe_get(log, 'event', 'outcome'),
                        "severity": safe_get(log, 'event', 'severity'),
                        "category": safe_get(log, 'event', 'category'),
                        "action": safe_get(log, 'event', 'action'),
                        "reason": safe_get(log, 'event', 'reason'),
                        "http_method": safe_get(log, 'http', 'request', 'method'),
                        "http_status": safe_get(log, 'http', 'response', 'status_code'),
                        "url_path": safe_get(log, 'url', 'path'),
                        "user_agent": safe_get(log, 'user_agent', 'original'),
                        "attack_type": safe_get(log, 'attack', 'technique'),
                        "attack_confidence": safe_get(log, 'attack', 'confidence'),
                        "labels": log.get('labels'),
                        "message": log.get('message'),
                        "raw": Json(log),
                        "destination_ip": safe_get(log, 'destination', 'ip'),
                        "destination_port": safe_get(log, 'destination', 'port'),
                        "protocol": safe_get(log, 'network', 'transport'),

                    }
                )
        print("[*] Log successfully inserted into the database.")
    except Exception as e:
        print(f"[!] Error inserting log into database: {e}")
        print(f"Failed log data: {log}")