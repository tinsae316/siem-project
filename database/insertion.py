# insert.py
import os
from dotenv import load_dotenv
import psycopg

load_dotenv()
conninfo = os.environ["DATABASE_URL"]

def insert_log(log: dict):
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
                "timestamp": log.get("timestamp"),  # can be None for default
                "source_ip": log.get("source_ip"),
                "source_port": log.get("source_port"),
                "username": log.get("username"),
                "host": log.get("host"),
                "outcome": log.get("outcome"),
                "severity": log.get("severity"),
                "category": log.get("category"),
                "action": log.get("action"),
                "reason": log.get("reason"),
                "http_method": log.get("http_method"),
                "http_status": log.get("http_status"),
                "url_path": log.get("url_path"),
                "user_agent": log.get("user_agent"),
                "attack_type": log.get("attack_type"),
                "attack_confidence": log.get("attack_confidence"),
                "labels": log.get("labels"),
                "message": log.get("message"),
                "raw": psycopg.types.json.Json(log.get("raw") or log)
            })
            return cur.fetchone()[0]
