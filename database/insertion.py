# database/insertion.py
import os
from dotenv import load_dotenv
import psycopg
from psycopg.types.json import Json

load_dotenv()
conninfo = os.environ["DATABASE_URL"]

def insert_log(log: dict) -> int:
    """
    Inserts a log record into the database.
    
    Args:
        log: A flattened dictionary matching the database columns.
             
    Returns:
        The ID of the newly inserted log record.
    """
    with psycopg.connect(conninfo) as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO logs (
                  timestamp, source_ip, source_port, username, host, outcome, severity,
                  category, action, reason, http_method, http_status, url_path, user_agent,
                  attack_type, attack_confidence, labels, message, raw
                ) VALUES (
                  %(timestamp)s, %(source_ip)s, %(source_port)s, %(username)s, %(host)s,
                  %(outcome)s, %(severity)s, %(category)s, %(action)s, %(reason)s,
                  %(http_method)s, %(http_status)s, %(url_path)s, %(user_agent)s,
                  %(attack_type)s, %(attack_confidence)s, %(labels)s, %(message)s, %(raw)s
                ) RETURNING id;
            """, {
                **log,  # This unpacks all key-value pairs from the log dictionary
                "raw": Json(log.get("raw")) # Ensure 'raw' is serialized as JSON
            })
            return cur.fetchone()[0]