from __future__ import annotations

import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from app.core.observability import log_event

logger = logging.getLogger("seagull.api.realtime.admission")

PORTAL_REALTIME_CONNECTION_LEDGER_PREFIX = "seagull:portal:realtime:v3:conn"

_ADMISSION_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])
local max_connections = tonumber(ARGV[3])
local member = ARGV[4]
redis.call('ZREMRANGEBYSCORE', key, '-inf', now - ttl)
local active = redis.call('ZCARD', key)
if active >= max_connections then
  return {0, active}
end
redis.call('ZADD', key, now, member)
redis.call('EXPIRE', key, ttl * 2)
return {1, active + 1}
"""


def connection_ledger_key(user_id: int) -> str:
    return f"{PORTAL_REALTIME_CONNECTION_LEDGER_PREFIX}:{int(user_id)}"


def _coerce_admission_result(result: Any) -> tuple[bool, int]:
    try:
        admitted_raw, active_raw = result[0], result[1]
        return int(admitted_raw) == 1, max(0, int(active_raw))
    except Exception:
        return True, 0


@dataclass
class ConnectionAdmission:
    admitted: bool
    reason: str
    active_connections: int
    _ledger: Optional["PortalRealtimeConnectionLedger"] = None
    _connection_id: str = ""
    _user_id: int = 0
    _released: bool = False
    _last_renew_monotonic: float = field(default_factory=time.monotonic)

    def renew(self) -> None:
        ledger = self._ledger
        if ledger is None or self._released or not self._connection_id:
            return
        now_monotonic = time.monotonic()
        if now_monotonic - self._last_renew_monotonic < ledger.renew_interval_seconds:
            return
        self._last_renew_monotonic = now_monotonic
        ledger.touch(user_id=self._user_id, connection_id=self._connection_id)

    def release(self) -> None:
        ledger = self._ledger
        already_released = self._released
        self._released = True
        if ledger is None or already_released or not self._connection_id:
            return
        ledger.remove(user_id=self._user_id, connection_id=self._connection_id)


class PortalRealtimeConnectionLedger:
    def __init__(
        self,
        redis_client: Any,
        *,
        max_connections_per_user: int,
        connection_ttl_seconds: int,
    ) -> None:
        self._redis = redis_client
        self.max_connections_per_user = max(1, int(max_connections_per_user))
        self.connection_ttl_seconds = max(1, int(connection_ttl_seconds))
        self.renew_interval_seconds = max(1.0, self.connection_ttl_seconds / 3.0)

    def admit(self, *, user_id: int) -> ConnectionAdmission:
        connection_id = secrets.token_hex(16)
        if self._redis is None:
            return ConnectionAdmission(admitted=True, reason="ledger_unavailable", active_connections=0)

        key = connection_ledger_key(user_id)
        now = time.time()
        try:
            result = self._redis.eval(
                _ADMISSION_LUA,
                1,
                key,
                str(now),
                str(self.connection_ttl_seconds),
                str(self.max_connections_per_user),
                connection_id,
            )
        except Exception as exc:
            log_event(
                logger,
                "warning",
                "realtime_admission_ledger_error",
                stage="admit",
                error_type=type(exc).__name__,
                error=str(exc),
            )
            return ConnectionAdmission(admitted=True, reason="ledger_unavailable", active_connections=0)

        admitted, active = _coerce_admission_result(result)
        if not admitted:
            return ConnectionAdmission(admitted=False, reason="concurrency_limit", active_connections=active)
        return ConnectionAdmission(
            admitted=True,
            reason="admitted",
            active_connections=active,
            _ledger=self,
            _connection_id=connection_id,
            _user_id=int(user_id),
        )

    def touch(self, *, user_id: int, connection_id: str) -> None:
        if self._redis is None or not connection_id:
            return
        key = connection_ledger_key(user_id)
        now = time.time()
        try:
            pipe = self._redis.pipeline()
            pipe.zadd(key, {connection_id: now})
            pipe.expire(key, self.connection_ttl_seconds * 2)
            pipe.execute()
        except Exception:
            pass

    def remove(self, *, user_id: int, connection_id: str) -> None:
        if self._redis is None or not connection_id:
            return
        key = connection_ledger_key(user_id)
        try:
            self._redis.zrem(key, connection_id)
        except Exception:
            pass
