import os
from dotenv import load_dotenv
import psycopg

# load environment variables (POSTGRES_URL)
load_dotenv()
conninfo = os.environ["DATABASE_URL"]

def get_recent_logs(limit: int = 100):
    """
    Return the most recent logs, default limit 100.
    """
    with psycopg.connect(conninfo) as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT *
                FROM logs
                ORDER BY timestamp DESC
                LIMIT %s;
            """, (limit,))
            # fetch all rows as a list of tuples
            rows = cur.fetchall()
            return rows

def get_log_by_id(log_id: int):
    """
    Return a single log row by its id.
    """
    with psycopg.connect(conninfo) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM logs WHERE id = %s;", (log_id,))
            row = cur.fetchone()
            return row

def get_logs_by_severity(severity: int, limit: int = 100):
    """
    Return logs filtered by severity.
    """
    with psycopg.connect(conninfo) as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT *
                FROM logs
                WHERE severity = %s
                ORDER BY timestamp DESC
                LIMIT %s;
            """, (severity, limit))
            rows = cur.fetchall()
            return rows
