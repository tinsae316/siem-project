# collector/main.py
import uvicorn
from fastapi import FastAPI, HTTPException
from contextlib import asynccontextmanager
from collector.schemas import LogSchema
# This import is correct
from collector.db import insert_log, init_db
from collector.file_watcher import watch_files_with_pool
import asyncio

db_pool = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handles the application startup and shutdown events."""
    global db_pool
    db_pool = await init_db()
    file_watcher_task = asyncio.create_task(watch_files_with_pool(db_pool))
    yield
    file_watcher_task.cancel()
    try:
        await file_watcher_task
    except asyncio.CancelledError:
        print("[*] File watcher task stopped.")
    finally:
        # psycop_pool uses .close() for async pool cleanup
        await db_pool.close()
        print("[*] Database connection pool closed.")

app = FastAPI(title="SIEM Collector", lifespan=lifespan)

@app.post("/collect")
async def collect_log(log: LogSchema):
    """
    API endpoint to ingest logs via HTTP.
    """
    try:
        log_dict = log.dict()
        await insert_log(db_pool, log_dict)
        return {"status": "ok", "message": "Log received"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run("collector.main:app", host="0.0.0.0", port=8000, reload=True)