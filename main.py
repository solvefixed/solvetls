from asyncio import CancelledError, current_task, get_running_loop, run
from contextlib import suppress
from signal import SIGTERM

from constants import (
    CERT_PATH,
    HOST_IP,
    HTTP_PORT,
    KEY_PATH,
    LOG_LEVEL,
    MONGODB_URL,
    PORT,
)
from solvetls import SolveTLS, close_storage, init_storage, setup_logging


async def main():
    try:
        tls_server = SolveTLS(cert_file=CERT_PATH, key_file=KEY_PATH)
    except FileNotFoundError:
        raise SystemExit(
            "Cannot start solvetls: TLS certificate or private key not found.\n"
            f"Certificate: {CERT_PATH}\n"
            f"Private key: {KEY_PATH}\n"
            "Provide these files or set SOLVETLS_CERT and SOLVETLS_KEY.\n"
            "See README.md (Certificates) for setup."
        ) from None
    except PermissionError:
        raise SystemExit(
            "Cannot start solvetls: TLS certificate or private key is not readable.\n"
            f"Certificate: {CERT_PATH}\n"
            f"Private key: {KEY_PATH}\n"
            "Grant the server user read access to these files.\n"
            "See README.md (Certificates) for setup."
        ) from None

    loop = get_running_loop()
    signal_installed = False
    try:
        # Docker sends SIGTERM. asyncio.run already handles Ctrl-C cancellation.
        with suppress(NotImplementedError):
            loop.add_signal_handler(SIGTERM, current_task().cancel)
            signal_installed = True
        await init_storage(MONGODB_URL)
        await tls_server.start(host=HOST_IP, port=PORT, http_port=HTTP_PORT)
        await tls_server.serve_forever()
    finally:
        try:
            await tls_server.close()
        finally:
            await close_storage()
            if signal_installed:
                loop.remove_signal_handler(SIGTERM)


if __name__ == "__main__":
    setup_logging(LOG_LEVEL)
    with suppress(CancelledError, KeyboardInterrupt):
        run(main())
