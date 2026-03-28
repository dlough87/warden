"""
In-memory ring buffer for server log lines.
Attach memory_handler to the root logger at startup to capture all log output.
"""
import collections
import logging


class _MemoryHandler(logging.Handler):
    def __init__(self, maxlines: int = 500):
        super().__init__()
        self.lines: collections.deque[str] = collections.deque(maxlen=maxlines)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.lines.append(self.format(record))
        except Exception:
            pass


memory_handler = _MemoryHandler(maxlines=500)
