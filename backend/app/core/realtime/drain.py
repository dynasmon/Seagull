from __future__ import annotations

import logging
import signal
import threading
from typing import Any, Callable

from app.core.observability import log_event

logger = logging.getLogger("seagull.api.realtime.drain")


class RealtimeDrainController:
    def __init__(self) -> None:
        self._draining = False
        self._active: set[int] = set()
        self._sequence = 0
        self._lock = threading.Lock()
        self._signals_installed = False

    def is_draining(self) -> bool:
        return self._draining

    def begin_draining(self) -> None:
        self._draining = True

    def reset_state(self) -> None:
        with self._lock:
            self._draining = False
            self._active.clear()
            self._sequence = 0

    def register(self) -> int:
        with self._lock:
            self._sequence += 1
            token = self._sequence
            self._active.add(token)
            return token

    def deregister(self, token: int) -> None:
        with self._lock:
            self._active.discard(token)

    def active_connection_count(self) -> int:
        with self._lock:
            return len(self._active)

    def install_signal_handlers(self) -> None:
        if self._signals_installed:
            return
        self._signals_installed = True
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                previous = signal.getsignal(sig)
                signal.signal(sig, self._chained_handler(previous))
            except (ValueError, OSError, RuntimeError) as exc:
                log_event(
                    logger,
                    "warning",
                    "realtime_drain_signal_install_skipped",
                    signal=int(sig),
                    error_type=type(exc).__name__,
                )

    def _chained_handler(self, previous: Any) -> Callable[[int, Any], None]:
        def _handler(signum: int, frame: Any) -> None:
            self.begin_draining()
            if callable(previous):
                previous(signum, frame)

        return _handler


realtime_drain = RealtimeDrainController()
