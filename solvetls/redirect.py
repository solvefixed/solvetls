import logging
from asyncio import CancelledError, StreamReader, StreamWriter, timeout
from email.utils import formatdate
from http import HTTPStatus

from .http1 import HEAD_END, HTTP1Error, HTTP1Request, check_head_size, parse_request
from .uri import split_absolute_uri, validate_authority

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 10.0
DRAIN_TIMEOUT = 1.0
CLOSE_TIMEOUT = 1.0


def redirect_location(request: HTTP1Request, https_port: int) -> str:
    """Build an HTTPS location from a validated HTTP/1.1 request."""
    if request.method == "CONNECT":
        raise HTTP1Error("CONNECT tunnels are not supported", status_code=501)
    target = request.path
    if target == "*":
        raise HTTP1Error("A redirect requires a request path")
    if target.startswith("/"):
        authority = next(
            value for name, value in request.headers if name.lower() == "host"
        )
        path = target
    else:
        parsed = split_absolute_uri(target)
        if parsed.scheme not in ("http", "https"):
            raise HTTP1Error("Only HTTP request targets can be redirected")
        authority = parsed.netloc
        # Slice the original target so even a trailing empty '?' is preserved.
        path = target[len(parsed.scheme) + 3 + len(authority) :]
        if not path.startswith("/"):
            path = "/" + path
    host = validate_authority(authority)
    if not host:
        raise HTTP1Error("A redirect requires a host")
    if authority.startswith("["):
        host = f"[{host}]"
    port = "" if https_port == 443 else f":{https_port}"
    return f"https://{host}{port}{path}"


async def _read_head(reader: StreamReader) -> bytes:
    data = bytearray()
    while True:
        chunk = await reader.read(4096)
        if not chunk:
            if not data:
                return b""
            raise HTTP1Error("Request head was not terminated")
        data.extend(chunk)
        check_head_size(data, incomplete=True)
        end = data.find(HEAD_END)
        if end >= 0:
            return bytes(data[: end + len(HEAD_END)])


async def handle_redirect(
    reader: StreamReader, writer: StreamWriter, https_port: int
) -> None:
    try:
        location = None
        try:
            async with timeout(REQUEST_TIMEOUT):
                head = await _read_head(reader)
            if not head:
                return
            location = redirect_location(parse_request(head), https_port)
            status = HTTPStatus.PERMANENT_REDIRECT
        except HTTP1Error as error:
            status = HTTPStatus(error.status_code)
        except TimeoutError:
            status = HTTPStatus.REQUEST_TIMEOUT

        lines = [
            f"HTTP/1.1 {status.value} {status.phrase}",
            f"date: {formatdate(usegmt=True)}",
            "content-length: 0",
            "connection: close",
        ]
        if location is not None:
            lines.append(f"location: {location}")
        async with timeout(REQUEST_TIMEOUT):
            writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
            await writer.drain()
        # Send the redirect before draining an unread body; avoid a TCP reset
        # discarding the response when the client is still uploading.
        if writer.can_write_eof():
            writer.write_eof()
        async with timeout(DRAIN_TIMEOUT):
            while await reader.read(65536):
                pass
    except (OSError, TimeoutError) as error:
        logger.debug("HTTP redirect connection ended: %r", error)
    finally:
        try:
            writer.close()
            async with timeout(CLOSE_TIMEOUT):
                await writer.wait_closed()
        except CancelledError:
            writer.transport.abort()
            raise
        except Exception as error:
            writer.transport.abort()
            logger.debug("HTTP redirect transport close failed: %r", error)
