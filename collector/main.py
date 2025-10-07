import uvicorn
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from collector.schemas import LogSchema
from collector.parser import parse_log_line
from collector.db import insert_log, init_db
from collector.file_watcher import watch_files_with_pool
import asyncio

db_pool = None

@asynccontextmanager
async def lifespan(app: FastAPI):
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
        await db_pool.close()
        print("[*] Database connection pool closed.")

# ✅ app must be defined before you add routes
app = FastAPI(title="SIEM Collector", lifespan=lifespan)


# -----------------------------
# New /collect route
# -----------------------------
@app.post("/collect")
async def collect_log(request: Request):
    try:
        data = await request.json()

        # Case 1: structured logs
        try:
            log = LogSchema.parse_obj(data)
            log_dict = log.dict()
        except Exception:
            # Case 2: Filebeat log
            message = data.get("message")
            if not message:
                raise ValueError("No 'message' field found in Filebeat log")
            parsed = parse_log_line(message)
            if not parsed:
                raise ValueError(f"Could not parse log line: {message}")
            log_dict = parsed

        await insert_log(db_pool, log_dict)
        return JSONResponse(content={"status": "ok", "message": "Log received"})
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "error", "detail": str(e)})


if __name__ == "__main__":
    uvicorn.run("collector.main:app", host="0.0.0.0", port=8000, reload=True)
