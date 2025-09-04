# collector/main.py
import uvicorn
from fastapi import FastAPI, Request, HTTPException
from collector.schemas import LogSchema
from collector.db import insert_log
from collector.file_watcher import watch_files
import asyncio

app = FastAPI(title="SIEM Collector")

@app.post("/collect")
async def collect_log(log: LogSchema, request: Request):
    """
    API endpoint to ingest logs via HTTP.
    Example:
    curl -X POST http://localhost:8000/collect -H "Content-Type: application/json" -d '{...}'
    """
    try:
        log_dict = log.dict()
        await insert_log(log_dict)
        return {"status": "ok", "message": "Log received"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.on_event("startup")
async def startup_event():
    """Start file watcher as background task"""
    asyncio.create_task(watch_files())

if __name__ == "__main__":
    uvicorn.run("collector.main:app", host="0.0.0.0", port=8000, reload=True)
