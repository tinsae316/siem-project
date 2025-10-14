# collector/api.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional
from collector.db import init_db, fetch_logs
from datetime import datetime

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For development
    allow_methods=["*"],
    allow_headers=["*"],
)

db_pool = None

@app.on_event("startup")
async def startup():
    global db_pool
    db_pool = await init_db()

@app.get("/alerts")
async def get_alerts(limit: Optional[int] = 50, since: Optional[str] = None):
    """
    Fetch logs from DB. Optional 'since' ISO timestamp to fetch newer logs.
    """
    if not db_pool:
        return {"alerts": []}

    since_dt = None
    if since:
        try:
            since_dt = datetime.fromisoformat(since)
        except ValueError:
            since_dt = None

    logs = await fetch_logs(db_pool, limit=limit, since=since_dt)
    return {"alerts": logs}
