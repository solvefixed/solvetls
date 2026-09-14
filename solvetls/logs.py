import logging
from contextvars import ContextVar

connection_id: ContextVar[str] = ContextVar("connection_id", default="-")

LOG_FORMAT = "%(asctime)s %(levelname)-7s %(name)s [%(connection)s] %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
MAX_LOGGED_TEXT = 128


def loggable(value: str | None) -> str:
    """Escape and truncate client text to prevent log injection."""
    if not value:
        return "-"

    escaped = value[:MAX_LOGGED_TEXT].encode("unicode_escape").decode("ascii")
    return f"{escaped}..." if len(value) > MAX_LOGGED_TEXT else escaped


class ConnectionFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.connection = connection_id.get()
        return True


def setup_logging(level: str = "INFO"):
    """Log to stderr; raise on an unknown level name."""
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))
    # A handler filter also adds the connection ID to propagated records.
    handler.addFilter(ConnectionFilter())
    logging.basicConfig(level=level.upper(), handlers=[handler], force=True)

    # Suppress per-header HPACK debug output.
    logging.getLogger("hpack").setLevel(logging.INFO)
