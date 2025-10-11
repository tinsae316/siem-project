# collector/db.py
import os
import warnings
from datetime import datetime
from dotenv import load_dotenv
from psycopg_pool import AsyncConnectionPool
from psycopg.types.json import Json

load_dotenv()
DB_URL = os.getenv("DATABASE_URL", "postgresql://user:password@localhost:5432/siem")

# Suppress the specific RuntimeWarning from psycopg_pool
warnings.filterwarnings(
    "ignore", 
    message="opening the async pool AsyncConnectionPool in the constructor is deprecated and will not be supported anymore in a future release.",
    category=RuntimeWarning
)

def safe_get(data, *keys):
    """Safely gets a value from a nested dictionary, returning None if any key is missing."""
    for key in keys:
        if isinstance(data, dict):
            data = data.get(key)
        else:
            return None
    return data


async def init_db():
    """
    Create and open an AsyncConnectionPool, ensure the `logs` table exists,
    and return the opened pool. Do NOT use `open=True` in the constructor.
    """
    try:
        pool = AsyncConnectionPool(conninfo=DB_URL)  # don't use open=True here
        await pool.open()  # explicitly open
        print("[*] Database connection pool created and opened successfully.")

        # Ensure logs table exists
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    """
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
                    """
                )
        print("[*] 'logs' table checked/created successfully.")
        return pool
    except Exception as e:
        print(f"[!] Error initializing database: {e}")
        raise
