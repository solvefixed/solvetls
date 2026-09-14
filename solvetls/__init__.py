import logging

from .logs import setup_logging
from .server import SolveTLS
from .storage import close_storage, init_storage

# Suppress logging.lastResort when the application has no log handlers.
logging.getLogger(__name__).addHandler(logging.NullHandler())

__all__ = ["SolveTLS", "close_storage", "init_storage", "setup_logging"]
