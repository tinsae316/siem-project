# collector/db.py
import asyncpg
import os
from dotenv import load_dotenv

load_dotenv()

DB_URL = os.getenv("DATABASE_URL", "postgresql://user:password@localhost:5432/siem")

pool = None

async def init_db():
    global pool
    pool = await asyncpg.create_pool(DB_URL)

    async with pool.acquire() as conn:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMP,
                log JSONB
            )
        """)

async def insert_log(log: dict):
    global pool
    if pool is None:
        raise RuntimeError("Database pool not initialized. Call init_db() first.")

    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO logs (timestamp, log) VALUES ($1, $2)",
            log.get("timestamp"),   # ✅ matches schemas.py
            log
        )
