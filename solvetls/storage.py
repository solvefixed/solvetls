import logging
from asyncio import CancelledError, create_task, shield, timeout
from datetime import UTC, datetime

from beanie import Document, init_beanie
from pydantic import Field
from pymongo import AsyncMongoClient
from pymongo import timeout as database_timeout

logger = logging.getLogger(__name__)

_enabled = False
_client: AsyncMongoClient | None = None
INIT_TIMEOUT = 5.0
WRITE_TIMEOUT = 5.0
CLOSE_TIMEOUT = 5.0


class Fingerprint(Document):
    source: str | None = None
    ip: str | None = None
    http_version: str | None = None
    method: str | None = None
    user_agent: str | None = None
    error: str | None = None
    tls: dict | None = None
    http1: dict | None = None
    http2: dict | None = None
    tcpip: dict | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    class Settings:
        name = "fingerprints"


async def init_storage(connection_string: str) -> bool:
    """Replace storage; an empty URL disables it.

    The caller must finish pending writes and serialize storage lifecycle calls.
    Beanie stores document configuration process-wide.
    """
    global _enabled, _client

    await close_storage()
    if not connection_string:
        return False

    client = None
    try:
        with database_timeout(INIT_TIMEOUT):
            try:
                async with timeout(INIT_TIMEOUT):
                    client = AsyncMongoClient(
                        connection_string,
                        connectTimeoutMS=int(INIT_TIMEOUT * 1000),
                    )
                    await init_beanie(
                        database=client.get_default_database(),
                        document_models=[Fingerprint],
                    )
                _client = client
                _enabled = True
            finally:
                # Cleanup shares the deadline; close() can send endSessions.
                if not _enabled and client is not None:
                    await _close_client(client)
    except TimeoutError as error:
        raise TimeoutError(
            f"MongoDB initialization exceeded {INIT_TIMEOUT:g} seconds"
        ) from error

    logger.info("Storing fingerprints in MongoDB")
    return True


async def close_storage() -> None:
    """Disable writes and close the owned client after the server has stopped."""
    global _enabled, _client

    _enabled = False
    client, _client = _client, None
    if client is None:
        return
    await _close_client(client)


async def _close_client(client: AsyncMongoClient) -> None:
    # Cancellation must not interrupt the driver's cleanup halfway through.
    # Wait for cleanup before propagating cancellation to the caller.
    closing = create_task(_close_with_timeout(client))
    try:
        await shield(closing)
    except CancelledError:
        while not closing.done():
            try:
                await shield(closing)
            except CancelledError:
                continue
        raise


async def _close_with_timeout(client: AsyncMongoClient) -> None:
    try:
        # Limit network I/O while letting the driver finish closing pools and
        # monitors. An asyncio timeout would cancel that cleanup as well.
        # A nested driver deadline also preserves an earlier init deadline.
        with database_timeout(CLOSE_TIMEOUT):
            await client.close()
    except Exception:
        logger.exception("Failed to close MongoDB client")


async def save_fingerprint(report: dict) -> None:
    if not _enabled:
        return

    try:
        # Bound database I/O and the complete async insert, including ODM work.
        with database_timeout(WRITE_TIMEOUT):
            async with timeout(WRITE_TIMEOUT):
                await Fingerprint(**report).insert()
    except TimeoutError:
        logger.warning("Fingerprint write exceeded %.1f seconds", WRITE_TIMEOUT)
    except Exception:
        logger.exception("Failed to store fingerprint")
