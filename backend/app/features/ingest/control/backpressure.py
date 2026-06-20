from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Tuple

from app.core.cache import get_redis
from app.features.ingest.control.queue_keys import (
    _as_float,
    _as_int,
    _env_int,
    _env_str,
    _events_per_msg_avg_key,
    backlog_events_key,
    processing_key,
    queue_key,
)


@dataclass(frozen=True)
class BackpressureDecision:
    mode: str  # normal | rollup_only | reject_429
    reason: str
    backlog_events: int
    backlog_messages: int


def _update_events_per_msg_avg(r, sample_events_per_message: float) -> None:
    if sample_events_per_message <= 0:
        return
    try:
        key = _events_per_msg_avg_key()
        cur = _as_float(r.get(key), 1.0)
        nxt = (cur * 0.96) + (float(sample_events_per_message) * 0.04)
        if nxt < 1.0:
            nxt = 1.0
        r.setex(key, 3600, f"{nxt:.6f}")
    except Exception:
        return


def get_backlog() -> Tuple[int, int]:

    r = get_redis()
    if r is None:
        return 0, 0

    try:
        # Include items being processed by the worker.
        msgs = int(r.llen(queue_key())) + int(r.llen(processing_key()))
    except Exception:
        msgs = 0

    key = backlog_events_key()
    try:
        ev = _as_int(r.get(key), 0)
    except Exception:
        ev = 0

    # Self-heal common drift scenarios so pressure state can recover:
    # - zero messages but stale positive event counter
    # - counter far above plausible envelope for current queue depth
    try:
        avg = max(1.0, _as_float(r.get(_events_per_msg_avg_key()), 1.0))
        if msgs <= 0:
            if ev > 0:
                r.set(key, 0)
            ev = 0
        else:
            if ev < msgs:
                ev = msgs
                r.set(key, ev)
            else:
                plausible_upper = int(max(msgs * 10, msgs * avg * 8.0))
                if ev > plausible_upper:
                    ev = int(max(msgs, round(msgs * avg)))
                    r.set(key, ev)
    except Exception:
        pass

    # Never expose negative backlog values: they break backpressure decisions
    # and cause the platform to oscillate under load.
    return msgs, max(0, ev)


def evaluate_backpressure(*, received: int) -> BackpressureDecision:

    soft = max(1, _env_int("SEAGULL_INGEST_BACKPRESSURE_SOFT_BACKLOG_EVENTS", 50_000))
    hard = max(soft + 1, _env_int("SEAGULL_INGEST_BACKPRESSURE_HARD_BACKLOG_EVENTS", 200_000))
    soft_exit = max(0, _env_int("SEAGULL_INGEST_BACKPRESSURE_SOFT_EXIT_BACKLOG_EVENTS", int(soft * 0.6)))
    hard_exit = max(soft + 1, _env_int("SEAGULL_INGEST_BACKPRESSURE_HARD_EXIT_BACKLOG_EVENTS", int(hard * 0.75)))
    force_normal_max_msgs = max(0, _env_int("SEAGULL_INGEST_BACKPRESSURE_FORCE_NORMAL_MAX_MESSAGES", 4))
    mode = _env_str("SEAGULL_INGEST_BACKPRESSURE_MODE", "rollup_only").lower().strip()
    mode = mode if mode in {"rollup_only", "reject_429"} else "rollup_only"

    msgs, ev = get_backlog()
    r = get_redis()

    # Compute projected backlog to avoid races.
    projected = ev + max(0, int(received))
    prev_bp = ""
    if r is not None:
        try:
            prev_bp = str(r.get("seagull:ingest:bp_mode") or "").strip().lower()
        except Exception:
            prev_bp = ""

    selected = "normal"
    reason = "ok"

    if projected >= hard:
        selected = "reject_429" if mode == "reject_429" else "rollup_only"
        reason = "hard_backlog"
    elif projected >= soft:
        selected = "rollup_only"
        reason = "soft_backlog"
    elif prev_bp == "reject_429" and projected >= hard_exit:
        selected = "reject_429" if mode == "reject_429" else "rollup_only"
        reason = "hard_backlog_hysteresis"
    elif prev_bp in {"reject_429", "rollup_only"} and projected >= soft_exit:
        selected = "rollup_only"
        reason = "soft_backlog_hysteresis"

    # Recovery fast-path:
    # if queue depth is already tiny, do not keep normal traffic in rollup_only
    # just because a stale event counter is slightly above the soft-exit threshold.
    if selected != "normal" and projected < soft and msgs <= force_normal_max_msgs:
        selected = "normal"
        reason = "recovery_small_queue"

    if r is not None:
        try:
            r.setex("seagull:ingest:bp_mode", 30, selected)
        except Exception:
            pass

    return BackpressureDecision(mode=selected, reason=reason, backlog_events=ev, backlog_messages=msgs)


def enqueue_ingest_message(*, message: Dict[str, Any], received: int) -> bool:
    r = get_redis()
    if r is None:
        return False

    payload = json.dumps(message, separators=(",", ":"), ensure_ascii=False)

    try:
        pipe = r.pipeline()
        pipe.rpush(queue_key(), payload)
        pipe.incrby(backlog_events_key(), int(received))
        pipe.execute()
        _update_events_per_msg_avg(r, float(max(1, int(received))))
        return True
    except Exception:
        return False
