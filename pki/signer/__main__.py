from __future__ import annotations

import logging
import signal
import sys
import threading
from types import FrameType
from typing import Optional

from signer import config as _config
from signer.server import SigningServer, logger

LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"


def main() -> int:
    logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
    try:
        settings = _config.load()
    except _config.ConfigurationError as exc:
        logger.error("refusing to start: %s", exc)
        return 2

    server = SigningServer(settings)

    def _stop(signum: int, frame: Optional[FrameType]) -> None:
        logger.info("stopping on signal %s", signum)
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    logger.info("signing agent certificates on %s:%s", settings.host, server.bound_port)
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
