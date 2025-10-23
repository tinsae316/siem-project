# collector/file_watcher.py
import asyncio
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from collector.parser import parse_log_line
from collector.enhanced_db import insert_log_with_evolution

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(BASE_DIR, "test_logs")
LOG_FILE = os.path.join(LOG_DIR, "test.log")

class LogHandler(FileSystemEventHandler):
    """Handles new log lines and puts them into a queue."""
    def __init__(self, filename, queue):
        self.filename = filename
        self.queue = queue
        self.last_position = os.path.getsize(self.filename) if os.path.exists(self.filename) else 0

    def on_modified(self, event):
        if event.is_directory or os.path.abspath(event.src_path) != os.path.abspath(self.filename):
            return

        try:
            with open(self.filename, "r") as f:
                f.seek(self.last_position)
                new_lines = f.readlines()
                for line in new_lines:
                    line = line.strip()
                    if line:
                        self.queue.put_nowait(line)
                        print("[+] Detected new log:", line)
                self.last_position = f.tell()
        except Exception as e:
            print(f"[!] Error reading file {self.filename}: {e}")

async def log_consumer(pool, queue):
    """Consumes log lines from the queue and processes them."""
    while True:
        line = await queue.get()
        try:
            parsed = parse_log_line(line)
            if parsed:
                # Use enhanced insertion so new fields trigger schema evolution
                await insert_log_with_evolution(parsed)
        except Exception as e:
            print(f"Error processing log line: {e}")
        finally:
            queue.task_done()

async def watch_files_with_pool(pool):
    """Main function to set up file watching and log processing."""
    os.makedirs(LOG_DIR, exist_ok=True)
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, "a").close()

    queue = asyncio.Queue()
    event_handler = LogHandler(LOG_FILE, queue)

    observer = Observer()
    observer.schedule(event_handler, path=LOG_DIR, recursive=False)
    observer.start()

    print("[*] Watching log files for new events...")
    consumer_task = asyncio.create_task(log_consumer(pool, queue))

    try:
        while True:
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        print("[*] File watcher task was cancelled. Stopping observer...")
    finally:
        observer.stop()
        observer.join()
        await queue.join()