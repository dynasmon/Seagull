from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class NetworkTopologyWorkerState:
    cycle_count: int = 0
    last_refresh_t: float = 0.0
    last_ok_log_t: float = 0.0
    last_idle_log_t: float = 0.0
    last_recalc_token: str = ""
    pending_recalc_token: str = ""
    pending_reason: str = ""
    last_signal_stream_ids: dict[str, str] = field(default_factory=dict)

    def should_log_ok(self, every_s: float) -> bool:
        return every_s <= 0 or (time.time() - self.last_ok_log_t) >= every_s

    def mark_ok_logged(self) -> None:
        self.last_ok_log_t = time.time()

    def should_log_idle(self, every_s: float) -> bool:
        return every_s <= 0 or (time.time() - self.last_idle_log_t) >= every_s

    def mark_idle_logged(self) -> None:
        self.last_idle_log_t = time.time()

