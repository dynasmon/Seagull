"""Protocol Intelligence (deep network metadata).

This package is used by the backend workers to derive higher-level protocol metadata from:
- raw L7 bytes (when present in event.extra)
- lightweight heuristics (ports/transport) when raw payload is not available

Design goals:
- Pure-stdlib (no heavy DPI deps)
- Safe-by-default parsing (caps, recursion limits)
- Idempotent output (writes are additive; marker fields prevent rework)

The worker stores derived metadata in net_events.extra so the API can aggregate without
reprocessing packets.
"""

from .analyzer import analyze_event

__all__ = ["analyze_event"]
