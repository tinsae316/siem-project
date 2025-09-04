# collector/file_watcher.py
import asyncio
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from collector.parser import parse_log_line
from collector.db import insert_log

LOG_FILES = [
    "/var/log/auth.log",      # SSH auth
    "/var/log/nginx/access.log",  # Web access
    # Add more log files here if needed
]

class LogHandler(FileSystemEventHandler):
    """Handles new log lines in watched files."""

    def __init__(self, file_path):
        self.file_path = file_path
        self._seek_end()

    def _seek_end(self):
        # Open file and move pointer to end
        self.file = open(self.file_path, "r")
        self.file.seek(0, 2)  # move to EOF

    def on_modified(self, event):
        if event.src_path == self.file_path:
            # Read new lines
            for line in self.file:
                parsed = parse_log_line(line)
                if parsed:
                    # Send to DB asynchronously
                    asyncio.create_task(insert_log(parsed))

async def watch_files():
    observers = []

    for file_path in LOG_FILES:
        event_handler = LogHandler(file_path)
        observer = Observer()
        observer.schedule(event_handler, path=file_path, recursive=False)
        observer.start()
        observers.append(observer)

    print("[*] Watching log files for new events...")
    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("[*] Stopping observers...")
        for obs in observers:
            obs.stop()
        for obs in observers:
            obs.join()

if __name__ == "__main__":
    asyncio.run(watch_files())
