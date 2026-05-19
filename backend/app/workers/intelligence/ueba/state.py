from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass
class UebaWorkerState:
    cycle_count: int = 0
    last_ok_log_t: float = 0.0

    def should_log_ok(self, every_s: float) -> bool:
        return every_s <= 0 or (time.time() - self.last_ok_log_t) >= every_s

    def mark_ok_logged(self) -> None:
        self.last_ok_log_t = time.time()
