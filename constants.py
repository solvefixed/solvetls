import logging
import os


def _parse_port(name: str, value: str) -> int:
    message = f"Cannot start solvetls: {name} must be an integer between 0 and 65535."
    try:
        port = int(value)
    except ValueError:
        raise SystemExit(message) from None
    if not 0 <= port <= 65535:
        raise SystemExit(message)
    return port


HOST_IP = os.getenv("SOLVETLS_HOST", "0.0.0.0")  # noqa: S104
PORT = _parse_port("SOLVETLS_PORT", os.getenv("SOLVETLS_PORT", "443"))
_http_port = os.getenv("SOLVETLS_HTTP_PORT", "80")
HTTP_PORT = _parse_port("SOLVETLS_HTTP_PORT", _http_port) if _http_port else None

CERT_PATH = os.getenv("SOLVETLS_CERT", "certs/fullchain.pem")
KEY_PATH = os.getenv("SOLVETLS_KEY", "certs/privkey.pem")

# Include the database name in the URI; empty disables storage.
MONGODB_URL = os.getenv("SOLVETLS_MONGODB_URL", "")

LOG_LEVEL = os.getenv("SOLVETLS_LOG_LEVEL", "INFO").upper()
if LOG_LEVEL not in logging.getLevelNamesMapping():
    raise SystemExit(
        "Cannot start solvetls: SOLVETLS_LOG_LEVEL must be one of "
        + ", ".join(sorted(logging.getLevelNamesMapping()))
        + "."
    )
